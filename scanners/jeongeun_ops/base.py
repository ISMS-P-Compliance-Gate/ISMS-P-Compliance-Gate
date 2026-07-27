"""
정은 파트 공통 베이스 클래스
scanners/jeongeun_ops/ 하위 6개 check_*.py가 공유

각 check_*.py는 ISMSRule을 상속해서 check() 메서드에 "무엇을 점검할지"만
구현하면 된다. run_id/commit_sha/pr_number를 읽어오는 것, 예외를 ERROR
결과로 바꿔주는 것, lib.mapping.to_isms_result()에 맞는 dict를 만들어
저장하는 것은 여기서 한 번만 처리한다.
"""
import os
import sys
import traceback
from abc import ABC, abstractmethod
from pathlib import Path
from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
load_dotenv(REPO_ROOT / ".env")  # 로컬 실행 시 .env 로드 (CI에는 .env 없어 조용히 무시)

from lib.mapping import to_isms_result  # noqa: E402

OWNER = "정은"

# sample_targets 폴더 경로 (mock 모드에서 각 룰이 참조)
SAMPLE_DIR = Path(__file__).parent / "sample_targets"


def finding(
    message: str,
    severity: str = "MEDIUM",
    file: str | None = None,
    line: int | None = None,
) -> dict:
    """schema/isms-p-result.schema.json의 findings 항목 포맷에 맞춰 dict 생성."""
    if severity not in {"HIGH", "MEDIUM", "LOW", "INFO"}:
        raise ValueError(f"severity는 HIGH/MEDIUM/LOW/INFO 중 하나여야 함: {severity}")
    return {"message": message, "severity": severity, "file": file, "line": line}


def is_mock() -> bool:
    """MOCK_MODE 환경변수 확인. true/1이면 sample_targets 사용."""
    return os.getenv("MOCK_MODE", "false").lower() in ("true", "1")


class ISMSRule(ABC):
    control_id: str
    control_name: str
    category: str   # "auto" | "semi-auto" | "checklist"
    tool: str

    def __init__(self):
        self.run_id     = os.getenv("GITHUB_RUN_ID", "local")
        self.commit_sha = os.getenv("GITHUB_SHA")
        pr_number       = os.getenv("PR_NUMBER")
        self.pr_number  = int(pr_number) if pr_number else None

    @abstractmethod
    def check(self) -> dict:
        """
        점검 로직을 구현하고 아래 형태의 dict를 반환한다.

        {
            "status": "PASS" | "FAIL" | "NOT_APPLICABLE" | "MANUAL_REQUIRED",
            "findings": [finding(...), ...],   # 없으면 빈 리스트도 OK
            "scope": "...",                    # category == "semi-auto"일 때만 필수
            "checklist_items": [...],          # category == "checklist"일 때만 필수
        }
        """
        raise NotImplementedError

    def run(self) -> dict:
        try:
            outcome          = self.check()
            status           = outcome.get("status", "ERROR")
            findings         = outcome.get("findings", [])
            scope            = outcome.get("scope")
            checklist_items  = outcome.get("checklist_items")
        except Exception as exc:
            # 점검 스크립트 하나의 예외가 전체 파이프라인을 죽이지 않도록
            traceback.print_exc()
            status           = "ERROR"
            findings         = [finding(f"점검 스크립트 실행 중 예외 발생: {exc}", severity="HIGH")]
            scope            = None
            checklist_items  = None

        result = to_isms_result(
            run_id          = self.run_id,
            control_id      = self.control_id,
            control_name    = self.control_name,
            category        = self.category,
            status          = status,
            tool            = self.tool,
            owner           = OWNER,
            findings        = findings,
            checklist_items = checklist_items,
            scope           = scope,
            pr_number       = self.pr_number,
            commit_sha      = self.commit_sha,
        )
        print(
            f"[{self.control_id}] {self.control_name}: "
            f"{status} (findings={len(findings)}) -> {result['evidence_path']}"
        )
        return result
