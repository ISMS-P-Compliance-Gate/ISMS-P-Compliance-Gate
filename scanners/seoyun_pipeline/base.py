"""
7개 점검 스크립트(check_2_5_1.py ~ check_2_9_1.py)가 공유하는 베이스 클래스.

각 check_*.py는 ISMSRule을 상속해서 check() 메서드에 "무엇을 점검할지"만
구현하면 된다. run_id/commit_sha/pr_number를 읽어오는 것, 예외를 ERROR
결과로 바꿔주는 것, lib.mapping.to_isms_result()에 맞는 dict를 만들어
저장하는 것은 여기서 한 번만 처리한다..
"""
#11


import os
import sys
import time
import traceback
from abc import ABC, abstractmethod

import requests
from dotenv import load_dotenv

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path.insert(0, REPO_ROOT)
load_dotenv(os.path.join(REPO_ROOT, ".env"))  # 로컬 실행 시 .env를 환경변수로 로드 (CI에는 .env가 없어 조용히 무시됨)
from lib.mapping import to_isms_result  # noqa: E402

OWNER = "서윤"
GITHUB_API = "https://api.github.com"
DEFAULT_TIMEOUT = 10  # seconds, 모든 외부 API 호출 공통 타임아웃
RATE_LIMIT_MAX_RETRIES = 3


def finding(message: str, severity: str = "MEDIUM", file: str | None = None, line: int | None = None) -> dict:
    """schema/isms-p-result.schema.json의 findings 항목 포맷에 맞춰 dict 생성."""
    if severity not in {"HIGH", "MEDIUM", "LOW", "INFO"}:
        raise ValueError(f"severity는 HIGH/MEDIUM/LOW/INFO 중 하나여야 함: {severity}")
    return {"message": message, "severity": severity, "file": file, "line": line}


def github_session() -> requests.Session:
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN 환경변수가 설정되지 않았습니다")
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    return session


def repo_full_name() -> str:
    repo = os.getenv("GITHUB_REPOSITORY")
    if not repo:
        raise RuntimeError("GITHUB_REPOSITORY 환경변수가 설정되지 않았습니다 (예: owner/repo)")
    return repo


def org_name() -> str:
    org = os.getenv("GITHUB_ORG")
    if not org:
        raise RuntimeError("GITHUB_ORG 환경변수가 설정되지 않았습니다")
    return org


def _is_rate_limited(resp: requests.Response) -> bool:
    return resp.status_code == 403 and resp.headers.get("X-RateLimit-Remaining") == "0"


def _rate_limit_wait_seconds(resp: requests.Response) -> float:
    retry_after = resp.headers.get("Retry-After")
    if retry_after:
        return float(retry_after)
    reset_at = resp.headers.get("X-RateLimit-Reset")
    if reset_at:
        return max(float(reset_at) - time.time(), 1.0)
    return 5.0


def request_with_retry(session: requests.Session, method: str, url: str, **kwargs) -> requests.Response:
    """timeout을 기본 적용하고, GitHub rate limit(403 + X-RateLimit-Remaining=0)에 걸리면
    리셋 시각까지 대기 후 재시도한다."""
    kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
    resp = session.request(method, url, **kwargs)
    for _ in range(RATE_LIMIT_MAX_RETRIES):
        if not _is_rate_limited(resp):
            break
        time.sleep(_rate_limit_wait_seconds(resp))
        resp = session.request(method, url, **kwargs)
    return resp


def paginate(session: requests.Session, url: str, params: dict | None = None):
    """GitHub REST API의 Link 헤더 기반 페이지네이션을 순회하며 item을 하나씩 yield."""
    while url:
        resp = request_with_retry(session, "GET", url, params=params)
        resp.raise_for_status()
        yield from resp.json()
        url = resp.links.get("next", {}).get("url")
        params = None  # 다음 페이지 URL에 쿼리가 이미 포함되어 있음


class ISMSRule(ABC):
    control_id: str
    control_name: str
    category: str  # "auto" | "semi-auto" | "checklist"
    tool: str

    def __init__(self):
        self.run_id = os.getenv("GITHUB_RUN_ID", "local")
        self.commit_sha = os.getenv("GITHUB_SHA")
        pr_number = os.getenv("PR_NUMBER")
        self.pr_number = int(pr_number) if pr_number else None

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
            outcome = self.check()
            status = outcome.get("status", "ERROR")
            findings = outcome.get("findings", [])
            scope = outcome.get("scope")
            checklist_items = outcome.get("checklist_items")
        except Exception as exc:  # 점검 스크립트 하나의 예외가 전체 파이프라인을 죽이지 않도록
            traceback.print_exc()
            status = "ERROR"
            findings = [finding(f"점검 스크립트 실행 중 예외 발생: {exc}", severity="HIGH")]
            scope = None
            checklist_items = None

        result = to_isms_result(
            run_id=self.run_id,
            control_id=self.control_id,
            control_name=self.control_name,
            category=self.category,
            status=status,
            tool=self.tool,
            owner=OWNER,
            findings=findings,
            checklist_items=checklist_items,
            scope=scope,
            pr_number=self.pr_number,
            commit_sha=self.commit_sha,
        )
        print(f"[{self.control_id}] {self.control_name}: {status} (findings={len(findings)}) -> {result['evidence_path']}")
        return result
