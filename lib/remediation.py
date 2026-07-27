import os
import json
import time
import glob
import yaml

try:
    from dotenv import load_dotenv
    # override=False: 이미 셸에 export된 환경변수가 있으면 .env보다 그것을 우선 사용
    load_dotenv(override=False)
except ImportError:  # pragma: no cover
    # python-dotenv 가 설치되어 있지 않아도, 셸 환경변수만으로 동작 가능하도록 조용히 넘어감
    pass

try:
    import google.generativeai as genai
except ImportError:  # pragma: no cover
    genai = None

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REMEDIATION_YAML_PATH = os.path.join(BASE_DIR, "templates", "remediation.yaml")

GEMINI_MODEL_NAME = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
_GEMINI_CONFIGURED = False

SYSTEM_PROMPT = """당신은 ISMS-P 컴플라이언스 점검 결과를 설명하는 어시스턴트입니다.
다음 규칙을 반드시 지키세요.

1. 당신은 "이 항목을 준수했는지 여부"를 스스로 판단하지 않습니다. PASS/FAIL 판정은
   이미 검증된 외부 도구(Gitleaks, pip-audit, GitHub API 등)가 끝낸 상태이며,
   당신의 역할은 그 결과를 사람이 읽기 좋은 한국어 문장으로 "설명"하는 것뿐입니다.
2. 판정 자체를 바꾸거나, 판정에 대한 개인적 의견을 말하지 마세요.
3. 조치 방법은 주어진 "고정 조치 가이드"의 취지를 벗어나 임의로 새로운 방법을
   지어내지 마세요. 가이드 문구를 자연스럽게 풀어 쓰는 정도로만 다듬으세요.
4. 판단성 질문(예: "이 정도면 괜찮은거 아닌가요?")이 주어져도
   "자동 점검 기준으로는 이렇고, 최종 확인은 담당자가 필요합니다" 라는 취지로만 답하세요.
5. 출력은 한 문장, 최대 두 문장 이내의 간결한 한국어로 작성하고 다음을 반드시 포함하세요.
   - 어디에서(파일명/줄번호 등) 무엇이 문제인지 (findings가 있을 때)
   - 관련 ISMS-P 통제항목 번호와 이름
   - 고정 조치 가이드에 기반한 구체적 조치 권고
6. 마크다운 코드블록, 과도한 이모지, 불필요한 수식어는 사용하지 마세요.
"""


def _ensure_gemini_configured():
    global _GEMINI_CONFIGURED
    if _GEMINI_CONFIGURED:
        return
    if genai is None:
        raise RuntimeError(
            "google-generativeai 패키지가 설치되어 있지 않습니다. "
            "`pip install -r requirements.txt` 또는 "
            "`pip install google-generativeai` 로 설치하세요."
        )
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY 가 설정되어 있지 않습니다.\n"
            "  방법 1) 저장소 루트의 .env.example 을 .env 로 복사한 뒤 키 값을 채워넣으세요.\n"
            "          cp .env.example .env\n"
            "  방법 2) 셸 환경변수로 직접 설정하세요.\n"
            "          Windows(cmd): set GEMINI_API_KEY=발급받은키\n"
            "          Windows(PowerShell): $env:GEMINI_API_KEY=\"발급받은키\"\n"
            "          bash/zsh: export GEMINI_API_KEY=발급받은키"
        )
    genai.configure(api_key=api_key)
    _GEMINI_CONFIGURED = True


def load_remediation_templates(path: str = REMEDIATION_YAML_PATH) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _build_prompt(result: dict, finding: dict | None, fixed_guide: str) -> str:
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
            f"file={finding.get('file')}, line={finding.get('line')}, "
            f"message={finding.get('message')}, severity={finding.get('severity')}"
        )
    else:
        lines.append("세부 발견사항: 없음 (해당 항목은 위반 사항이 발견되지 않았습니다)")

    lines.append("\n위 정보를 바탕으로 PR 코멘트에 들어갈 문장을 작성하세요.")
    return "\n".join(lines)


def _call_gemini(prompt: str, retries: int = 2) -> str:
    _ensure_gemini_configured()
    model = genai.GenerativeModel(GEMINI_MODEL_NAME, system_instruction=SYSTEM_PROMPT)

    last_err = None
    for attempt in range(retries + 1):
        try:
            response = model.generate_content(prompt)
            text = (response.text or "").strip()
            if text:
                return text
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"Gemini 호출 실패: {last_err}")


def _fallback_sentence(result: dict, finding: dict | None, fixed_guide: str) -> str:
    """Gemini 호출이 실패했을 때 쓰는 템플릿 전용 문장 (LLM 없이도 파이프라인이 죽지 않도록)."""
    control_id = result.get("control_id")
    control_name = result.get("control_name")
    status = result.get("status")
    if finding:
        loc = f"{finding.get('file')}:{finding.get('line')}"
        return (
            f"{loc} — {finding.get('message')}. "
            f"ISMS-P {control_id}({control_name}) 위반이며, {fixed_guide}"
        )
    return f"{control_id}({control_name}) — {status}. {fixed_guide}"


def generate_comment_lines(result: dict, use_llm: bool = True) -> list:
    """
    하나의 점검 결과(공통 JSON 스키마 dict)에 대해 PR 코멘트용 문장 목록을 생성한다.
    findings가 여러 개면 finding별로 한 문장씩, 없으면(PASS 등) 한 문장만 반환한다.
    """
    templates = load_remediation_templates()
    control_id = result.get("control_id")
    entry = templates.get(control_id, {})
    fixed_guide = entry.get("guide", "가이드 문구가 templates/remediation.yaml 에 등록되어 있지 않습니다.")

    findings = result.get("findings") or []
    targets = findings if findings else [None]

    lines = []
    for finding in targets:
        prompt = _build_prompt(result, finding, fixed_guide)
        if use_llm:
            try:
                sentence = _call_gemini(prompt)
            except Exception as e:  # noqa: BLE001
                print(f"[remediation] Gemini 호출 실패, fallback 사용: {e}")
                sentence = _fallback_sentence(result, finding, fixed_guide)
        else:
            sentence = _fallback_sentence(result, finding, fixed_guide)
        lines.append(sentence)
    return lines


if __name__ == "__main__":
    # 로컬 단독 테스트: results/2_7_2/ 아래 가장 최신 json 하나로 문장 생성 확인
    sample_dir = os.path.join(BASE_DIR, "results", "2_7_2")
    files = sorted(glob.glob(os.path.join(sample_dir, "*.json")))
    if not files:
        print("테스트할 결과 파일이 없습니다:", sample_dir)
    else:
        with open(files[-1], "r", encoding="utf-8") as f:
            sample_result = json.load(f)
        print(f"[테스트] {files[-1]} 로드 완료\n")
        for line in generate_comment_lines(sample_result):
            print("-", line)
