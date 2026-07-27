"""
scripts/post_pr_comment.py
---------------------------

전체 파이프라인의 마지막 단계.

1. results/<control_id>/ 아래 각 폴더에서 "가장 최신" 점검 결과 json 을 수집한다.
2. lib/remediation.py 로 각 결과를 자연어 문장으로 변환한다.
3. 전체 충족률 요약 + 신호등(🟢/🔴) + 항목별 상세를 마크다운 코멘트로 조립한다.
4. GitHub Actions PR 컨텍스트에서 실행 중이면 실제 PR에 코멘트를 upsert(있으면 수정,
   없으면 새로 게시) 하고, 그 외(로컬 테스트, --dry-run)에는 파일로 저장 + 콘솔 출력만 한다.

사용법:
  로컬 테스트 (Gemini 포함):   python scripts/post_pr_comment.py --dry-run
  로컬 테스트 (LLM 생략, 빠르게 구조만 확인): python scripts/post_pr_comment.py --dry-run --no-llm
  GitHub Actions 안에서 실행:  python scripts/post_pr_comment.py

필요 패키지: pip install google-genai pyyaml requests python-dotenv
"""

import os
import sys
import glob
import json
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.remediation import generate_comments  # noqa: E402

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(BASE_DIR, "results")

# 우리 봇이 남긴 코멘트를 다음 실행에서 다시 찾아 "수정(upsert)"하기 위한 표식.
# 이 문자열이 body 안에 있으면 우리가 예전에 단 코멘트로 간주한다.
COMMENT_MARKER = "<!-- isms-p-compliance-gate:auto-comment -->"

STATUS_ICON = {"PASS": "🟢", "FAIL": "🔴", "SKIP": "⚪"}


def _load_json_items(path: str) -> list:
    """
    json 파일 하나를 읽어 dict 리스트로 반환한다.
    - 파일 내용이 dict 하나면 [dict]
    - 파일 내용이 list([dict, ...])면 그 리스트
    - 그 외(형식이 이상함)는 빈 리스트 + 경고 출력
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        return [data]

    if isinstance(data, list):
        items = [item for item in data if isinstance(item, dict)]
        skipped = len(data) - len(items)

        if skipped:
            print(f"[경고] {path} 안에 dict가 아닌 항목 {skipped}개는 건너뜀")

        return items

    print(f"[경고] 예상치 못한 파일 형식, 건너뜀: {path}")
    return []


def collect_latest_results() -> list:
    """
    results/ 아래를 재귀적으로 전부 스캔해서(폴더 구조든 평평한 구조든 상관없이)
    json에 담긴 control_id별로 timestamp가 가장 최신인 결과 하나씩만 골라 반환한다.


    폴더/파일명이 아니라 json 내용 안의 "control_id", "timestamp" 값을 기준으로
    판단하므로 저장 방식이 섞여 있어도 안전하게 동작한다.
    """
    if not os.path.isdir(RESULTS_DIR):
        return []

    all_json_paths = glob.glob(
        os.path.join(RESULTS_DIR, "**", "*.json"),
        recursive=True,
    )

    latest_by_control = {}

    for path in sorted(all_json_paths):
        for item in _load_json_items(path):
            control_id = item.get("control_id")

            if not control_id:
                print(f"[경고] control_id가 없는 항목 건너뜀: {path}")
                continue

            timestamp = item.get("timestamp", "")
            existing = latest_by_control.get(control_id)

            if existing is None or timestamp >= existing[0]:
                latest_by_control[control_id] = (timestamp, item)

    return [entry[1] for _, entry in sorted(latest_by_control.items())]


def build_comment_markdown(results: list, use_llm: bool = True) -> str:
    total = len(results)
    passed = sum(1 for r in results if r.get("status") == "PASS")
    rate = round(passed / total * 100) if total else 0

    generated_comments = generate_comments(
        results=results,
        use_llm=use_llm,
    )

    comment_by_control = {
        str(item.get("control_id")): item.get("comment", "")
        for item in generated_comments
    }

    lines = [COMMENT_MARKER, "## 🔎 ISMS-P Compliance Gate 점검 결과", ""]
    lines.append(f"**전체 {total}개 항목 중 {passed}개 PASS — {rate}%**")
    lines.append("")
    lines.append("| 상태 | 통제항목 | 결과 | 점검 시각 |")
    lines.append("|---|---|---|---|")

    for r in results:
        icon = STATUS_ICON.get(r.get("status"), "❔")

        lines.append(
            f"| {icon} | {r.get('control_id')} ({r.get('control_name')}) "
            f"| {r.get('status')} | {r.get('timestamp')} |"
        )

    lines.append("")
    lines.append("### 상세 내용")

    for r in results:
        icon = STATUS_ICON.get(r.get("status"), "❔")
        control_id = str(r.get("control_id"))

        lines.append(
            f"\n**{icon} {control_id} — {r.get('control_name')}**"
        )

        comment = comment_by_control.get(
            control_id,
            "코멘트를 생성하지 못했습니다.",
        )

        lines.append(f"- {comment}")

    return "\n".join(lines)


def _running_in_github_actions() -> bool:
    return bool(os.environ.get("GITHUB_ACTIONS")) and bool(
        os.environ.get("GITHUB_TOKEN")
    )


def post_to_github(comment_body: str):
    """
    GitHub Actions PR 컨텍스트에서 실제 PR에 코멘트를 upsert 한다.
    - 기존에 우리 봇이 남긴 코멘트(COMMENT_MARKER 포함)가 있으면 PATCH로 수정
    - 없으면 새로 POST

    필요 환경변수 (GitHub Actions가 기본 제공):
      GITHUB_TOKEN       - 워크플로우의 ${{ secrets.GITHUB_TOKEN }}
      GITHUB_REPOSITORY  - "owner/repo" 형태로 자동 세팅됨
      GITHUB_EVENT_PATH  - PR 이벤트 payload 파일 경로, 자동 세팅됨
    """
    import requests

    token = os.environ["GITHUB_TOKEN"]
    repo = os.environ["GITHUB_REPOSITORY"]

    event_path = os.environ.get("GITHUB_EVENT_PATH")

    if not event_path or not os.path.exists(event_path):
        raise RuntimeError(
            "GITHUB_EVENT_PATH 를 찾을 수 없습니다. PR 이벤트에서만 실행 가능합니다."
        )

    with open(event_path, "r", encoding="utf-8") as f:
        event = json.load(f)

    pr_number = event.get("pull_request", {}).get("number") or event.get("number")

    if not pr_number:
        raise RuntimeError("이벤트 payload에서 PR 번호를 찾을 수 없습니다.")

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }

    base_url = (
        f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    )

    # 기존 우리 봇 코멘트 검색 (upsert 하기 위함)
    existing_comment_id = None
    page = 1

    while True:
        resp = requests.get(
            base_url,
            headers=headers,
            params={"per_page": 100, "page": page},
        )

        resp.raise_for_status()
        comments = resp.json()

        if not comments:
            break

        for c in comments:
            if COMMENT_MARKER in c.get("body", ""):
                existing_comment_id = c["id"]
                break

        if existing_comment_id or len(comments) < 100:
            break

        page += 1

    if existing_comment_id:
        url = (
            f"https://api.github.com/repos/"
            f"{repo}/issues/comments/{existing_comment_id}"
        )

        resp = requests.patch(
            url,
            headers=headers,
            json={"body": comment_body},
        )

    else:
        resp = requests.post(
            base_url,
            headers=headers,
            json={"body": comment_body},
        )

    resp.raise_for_status()

    print(
        f"PR #{pr_number} 코멘트 게시 완료 "
        f"(status={resp.status_code})"
    )


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "GitHub에 실제로 올리지 않고 "
            "로컬 파일(pr_comment_preview.md)로만 저장"
        ),
    )

    parser.add_argument(
        "--no-llm",
        action="store_true",
        help=(
            "Gemini 호출 없이 템플릿 문장만으로 생성 "
            "(빠른 구조 확인용)"
        ),
    )

    args = parser.parse_args()

    results = collect_latest_results()

    if not results:
        print(
            f"results/ 에서 점검 결과를 찾지 못했습니다: "
            f"{RESULTS_DIR}"
        )
        return

    comment_body = build_comment_markdown(
        results,
        use_llm=not args.no_llm,
    )

    if args.dry_run or not _running_in_github_actions():
        out_path = os.path.join(
            BASE_DIR,
            "pr_comment_preview.md",
        )

        with open(out_path, "w", encoding="utf-8") as f:
            f.write(comment_body)

        print(
            "[dry-run] GitHub Actions 환경이 아니거나 "
            f"--dry-run 지정됨 → {out_path} 에 저장했습니다."
        )

        print("\n----- 미리보기 -----\n")
        print(comment_body)

    else:
        post_to_github(comment_body)


if __name__ == "__main__":
    main()
