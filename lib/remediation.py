"""
lib/remediation.py
------------------
Gemini를 이용해 점검 도구(gitleaks, pip-audit, GitHub API 등)의 원본 결과를
"ISMS-P 통제항목 + 고정 조치 가이드"와 결합하여 사람이 읽기 좋은 한국어 문장으로
다듬는 모듈.

핵심 원칙:
  - LLM은 PASS/FAIL을 스스로 판단하지 않는다.
  - 판정은 외부 점검 도구가 완료하며, LLM은 결과를 설명만 한다.
  - 조치 방법은 templates/remediation.yaml의 고정 가이드를 벗어나지 않는다.
  - Gemini 호출이 실패해도 fallback 문장을 사용하여 파이프라인을 계속 진행한다.

환경변수:
  GEMINI_API_KEY
    - 필수
    - Google AI Studio에서 발급받은 API 키

  GEMINI_MODEL
    - 선택
    - 기본값: gemini-3.6-flash

  GEMINI_REQUEST_INTERVAL_SECONDS
    - 선택
    - Gemini 요청 사이의 최소 간격
    - 기본값: 4.2초

  GEMINI_MAX_RETRIES
    - 선택
    - 최초 호출 실패 후 추가 재시도 횟수
    - 기본값: 2회

팀원 로컬 테스트 방법:
  1. 저장소 루트에서 .env.example을 .env로 복사
     cp .env.example .env

  2. .env 파일에 본인의 GEMINI_API_KEY 입력

  3. 의존성 설치
     pip install -r requirements.txt

  4. 테스트 실행
     python lib/remediation.py

주의:
  - .env 파일은 절대 Git에 커밋하지 않는다.
  - API 키를 Python 코드에 직접 입력하지 않는다.
  - GitHub Actions에서는 GitHub Secret을 통해 API 키를 전달한다.
"""

import glob
import json
import os
import time
from typing import Any

import yaml


# ============================================================================
# 기본 경로 설정
# ============================================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_PATH = os.path.join(BASE_DIR, ".env")
REMEDIATION_YAML_PATH = os.path.join(
    BASE_DIR,
    "templates",
    "remediation.yaml",
)


# ============================================================================
# 환경변수 로드
# ============================================================================

try:
    from dotenv import load_dotenv

    # override=False:
    # 운영환경이나 GitHub Actions에서 이미 설정된 환경변수를
    # 로컬 .env 파일이 덮어쓰지 않도록 한다.
    load_dotenv(dotenv_path=ENV_PATH, override=False)
except ImportError:  # pragma: no cover
    # python-dotenv가 없어도 셸/GitHub Actions 환경변수만으로 동작 가능
    pass


def _get_float_env(name: str, default: float) -> float:
    """환경변수를 float로 읽고, 잘못된 값이면 기본값을 반환한다."""
    raw_value = os.environ.get(name)

    if raw_value is None:
        return default

    try:
        return float(raw_value)
    except ValueError:
        print(
            f"[remediation] {name} 값이 숫자가 아니므로 "
            f"기본값 {default}을 사용합니다."
        )
        return default


def _get_int_env(name: str, default: int) -> int:
    """환경변수를 int로 읽고, 잘못된 값이면 기본값을 반환한다."""
    raw_value = os.environ.get(name)

    if raw_value is None:
        return default

    try:
        return int(raw_value)
    except ValueError:
        print(
            f"[remediation] {name} 값이 정수가 아니므로 "
            f"기본값 {default}을 사용합니다."
        )
        return default


GEMINI_MODEL_NAME = os.environ.get(
    "GEMINI_MODEL",
    "gemini-3.6-flash",
)

GEMINI_REQUEST_INTERVAL_SECONDS = max(
    0.0,
    _get_float_env(
        "GEMINI_REQUEST_INTERVAL_SECONDS",
        4.2,
    ),
)

GEMINI_MAX_RETRIES = max(
    0,
    _get_int_env(
        "GEMINI_MAX_RETRIES",
        2,
    ),
)


# ============================================================================
# Gemini SDK
# ============================================================================

try:
    from google import genai
    from google.genai import types
except ImportError:  # pragma: no cover
    genai = None
    types = None


_GEMINI_CLIENT = None
_LAST_REQUEST_STARTED_AT = 0.0


SYSTEM_PROMPT = """당신은 ISMS-P 컴플라이언스 점검 결과를 설명하는 어시스턴트입니다.
다음 규칙을 반드시 지키세요.

1. 당신은 "이 항목을 준수했는지 여부"를 스스로 판단하지 않습니다.
   PASS/FAIL 판정은 이미 검증된 외부 도구(Gitleaks, pip-audit,
   GitHub API 등)가 끝낸 상태이며, 당신의 역할은 그 결과를 사람이
   읽기 좋은 한국어 문장으로 설명하는 것뿐입니다.

2. 판정 자체를 바꾸거나 판정에 대한 개인적 의견을 말하지 마세요.

3. 조치 방법은 주어진 "고정 조치 가이드"의 취지를 벗어나
   임의로 새로운 방법을 지어내지 마세요.
   가이드 문구를 자연스럽게 풀어 쓰는 정도로만 다듬으세요.

4. 판단성 질문이 주어져도
   "자동 점검 기준에 따른 결과이며, 최종 확인은 담당자가 필요합니다"
   라는 취지로만 답하세요.

5. 출력은 한 문장, 최대 두 문장 이내의 간결한 한국어로 작성하고
   다음 내용을 반드시 포함하세요.
   - 어디에서 무엇이 문제인지
   - 관련 ISMS-P 통제항목 번호와 이름
   - 고정 조치 가이드에 기반한 조치 권고

6. 마크다운 코드블록, 과도한 이모지, 불필요한 수식어는 사용하지 마세요.
"""


def _get_gemini_client():
    """
    Gemini 클라이언트를 최초 한 번만 생성하여 재사용한다.

    API 키는 환경변수에서만 읽으며 코드에 직접 저장하지 않는다.
    """
    global _GEMINI_CLIENT

    if _GEMINI_CLIENT is not None:
        return _GEMINI_CLIENT

    if genai is None:
        raise RuntimeError(
            "google-genai 패키지가 설치되어 있지 않습니다. "
            "`pip install -r requirements.txt` 또는 "
            "`pip install google-genai`로 설치하세요."
        )

    api_key = os.environ.get("GEMINI_API_KEY", "").strip()

    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY가 설정되어 있지 않습니다.\n"
            "  방법 1) 저장소 루트의 .env.example을 .env로 복사한 뒤 "
            "API 키를 입력하세요.\n"
            "          cp .env.example .env\n"
            "  방법 2) 셸 환경변수로 설정하세요.\n"
            "          Windows(cmd): set GEMINI_API_KEY=발급받은키\n"
            "          Windows(PowerShell): "
            '$env:GEMINI_API_KEY="발급받은키"\n'
            "          bash/zsh: export GEMINI_API_KEY=발급받은키"
        )

    # 환경변수에서 읽은 키를 클라이언트 생성 시에만 전달한다.
    _GEMINI_CLIENT = genai.Client(api_key=api_key)

    return _GEMINI_CLIENT


def _wait_for_request_interval() -> None:
    """
    연속 Gemini 호출 사이에 최소 간격을 둔다.

    예:
      GEMINI_REQUEST_INTERVAL_SECONDS=4.2이면
      각 요청 시작 시점 사이에 최소 4.2초 간격을 유지한다.
    """
    global _LAST_REQUEST_STARTED_AT

    if GEMINI_REQUEST_INTERVAL_SECONDS <= 0:
        return

    now = time.monotonic()
    elapsed = now - _LAST_REQUEST_STARTED_AT
    remaining = GEMINI_REQUEST_INTERVAL_SECONDS - elapsed

    if remaining > 0:
        time.sleep(remaining)

    _LAST_REQUEST_STARTED_AT = time.monotonic()


def _sanitize_error(error: Exception) -> str:
    """
    오류 메시지에 API 키가 포함된 경우 노출되지 않도록 마스킹한다.
    """
    message = str(error)
    api_key = os.environ.get("GEMINI_API_KEY", "")

    if api_key:
        message = message.replace(api_key, "***REDACTED***")

    return message


def _is_retryable_error(error: Exception) -> bool:
    """
    일시적 오류인지 판단한다.

    인증 실패, 잘못된 요청, 존재하지 않는 모델 등은 기다려도
    해결되지 않으므로 재시도하지 않는다.
    """
    message = _sanitize_error(error).upper()

    non_retryable_keywords = (
        "INVALID_ARGUMENT",
        "PERMISSION_DENIED",
        "UNAUTHENTICATED",
        "API KEY NOT VALID",
        "API_KEY_INVALID",
        "NOT_FOUND",
    )

    return not any(
        keyword in message
        for keyword in non_retryable_keywords
    )


# ============================================================================
# 템플릿 및 프롬프트 생성
# ============================================================================

def load_remediation_templates(
    path: str = REMEDIATION_YAML_PATH,
) -> dict:
    """통제항목별 고정 조치 가이드를 YAML에서 불러온다."""
    with open(path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file) or {}


def _build_prompt(
    result: dict,
    finding: dict | None,
    fixed_guide: str,
) -> str:
    """점검 결과와 고정 조치 가이드를 Gemini 입력 형식으로 변환한다."""
    control_id = result.get("control_id")
    control_name = result.get("control_name")
    status = result.get("status")
    tool = result.get("tool")

    lines = [
        f"통제항목: {control_id} ({control_name})",
        f"판정 결과: {status}",
        f"사용 도구: {tool}",
        f"고정 조치 가이드: {fixed_guide}",
    ]

    if finding:
        lines.append(
            "세부 발견사항: "
            f"file={finding.get('file')}, "
            f"line={finding.get('line')}, "
            f"message={finding.get('message')}, "
            f"severity={finding.get('severity')}"
        )
    else:
        lines.append(
            "세부 발견사항: 없음 "
            "(해당 항목에서 위반 사항이 발견되지 않았습니다)"
        )

    lines.append(
        "\n위 정보를 바탕으로 PR 코멘트에 들어갈 문장을 작성하세요."
    )

    return "\n".join(lines)


# ============================================================================
# Gemini 호출
# ============================================================================

def _call_gemini(
    prompt: str,
    retries: int | None = None,
) -> str:
    """
    Gemini를 호출한다.

    - 요청 전 호출 간격을 적용한다.
    - 일시적인 오류는 지수 백오프로 재시도한다.
    - 최종 실패 시 RuntimeError를 발생시킨다.
    """
    client = _get_gemini_client()

    max_retries = (
        GEMINI_MAX_RETRIES
        if retries is None
        else max(0, retries)
    )

    last_error: Exception | None = None

    for attempt in range(max_retries + 1):
        _wait_for_request_interval()

        try:
            response = client.models.generate_content(
                model=GEMINI_MODEL_NAME,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_PROMPT,
                    max_output_tokens=300,
                    temperature=0.2,
                ),
            )

            text = (response.text or "").strip()

            if not text:
                raise RuntimeError(
                    "Gemini가 빈 응답을 반환했습니다."
                )

            return text

        except Exception as error:  # noqa: BLE001
            last_error = error

            # 재시도할 수 없는 오류이거나 마지막 시도라면 종료
            if (
                not _is_retryable_error(error)
                or attempt >= max_retries
            ):
                break

            # 5초 → 10초 → 20초 방식의 지수 백오프
            retry_wait_seconds = min(
                5 * (2 ** attempt),
                60,
            )

            print(
                "[remediation] Gemini 호출 일시 실패: "
                f"{_sanitize_error(error)}"
            )
            print(
                "[remediation] "
                f"{retry_wait_seconds}초 후 재시도합니다. "
                f"({attempt + 1}/{max_retries})"
            )

            time.sleep(retry_wait_seconds)

    raise RuntimeError(
        "Gemini 호출 실패: "
        f"{_sanitize_error(last_error or RuntimeError('알 수 없는 오류'))}"
    )


# ============================================================================
# Fallback 및 PR 코멘트 생성
# ============================================================================

def _fallback_sentence(
    result: dict,
    finding: dict | None,
    fixed_guide: str,
) -> str:
    """
    Gemini 호출에 실패했을 때 사용하는 템플릿 문장.

    LLM 없이도 파이프라인이 중단되지 않도록 한다.
    """
    control_id = result.get("control_id")
    control_name = result.get("control_name")
    status = result.get("status")

    if finding:
        file_name = finding.get("file") or "파일 위치 미확인"
        line_number = finding.get("line") or "줄 번호 미확인"
        message = finding.get("message") or "점검 위반사항 발견"

        location = f"{file_name}:{line_number}"

        return (
            f"{location} — {message}. "
            f"ISMS-P {control_id}({control_name}) 관련 사항으로, "
            f"{fixed_guide}"
        )

    return (
        f"ISMS-P {control_id}({control_name}) 점검 결과는 "
        f"{status}입니다. {fixed_guide}"
    )


def generate_comment_lines(
    result: dict,
    use_llm: bool = True,
) -> list[str]:
    """
    하나의 점검 결과에 대해 PR 코멘트용 문장 목록을 생성한다.

    findings가 여러 개면 finding별로 한 문장씩 생성한다.
    findings가 없으면 한 문장만 생성한다.
    """
    templates = load_remediation_templates()

    control_id = result.get("control_id")
    entry = templates.get(control_id, {})

    fixed_guide = entry.get(
        "guide",
        "가이드 문구가 templates/remediation.yaml에 "
        "등록되어 있지 않습니다.",
    )

    findings = result.get("findings") or []
    targets = findings if findings else [None]

    lines: list[str] = []

    for finding in targets:
        prompt = _build_prompt(
            result=result,
            finding=finding,
            fixed_guide=fixed_guide,
        )

        if use_llm:
            try:
                sentence = _call_gemini(prompt)
            except Exception as error:  # noqa: BLE001
                print(
                    "[remediation] Gemini 호출 실패, fallback 사용: "
                    f"{_sanitize_error(error)}"
                )

                sentence = _fallback_sentence(
                    result=result,
                    finding=finding,
                    fixed_guide=fixed_guide,
                )
        else:
            sentence = _fallback_sentence(
                result=result,
                finding=finding,
                fixed_guide=fixed_guide,
            )

        lines.append(sentence)

    return lines


# ============================================================================
# 로컬 테스트
# ============================================================================

if __name__ == "__main__":
    sample_dir = os.path.join(
        BASE_DIR,
        "results",
        "2_7_2",
    )

    files = sorted(
        glob.glob(
            os.path.join(sample_dir, "*.json")
        )
    )

    if not files:
        print(
            "테스트할 결과 파일이 없습니다:",
            sample_dir,
        )
    else:
        latest_file = files[-1]

        with open(
            latest_file,
            "r",
            encoding="utf-8",
        ) as file:
            sample_result: dict[str, Any] = json.load(file)

        print(f"[테스트] {latest_file} 로드 완료\n")
        print(
            "[테스트] 사용 모델:",
            GEMINI_MODEL_NAME,
        )
        print(
            "[테스트] 요청 간격:",
            f"{GEMINI_REQUEST_INTERVAL_SECONDS}초\n",
        )

        for line in generate_comment_lines(sample_result):
            print("-", line)
