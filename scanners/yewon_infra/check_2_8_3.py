# ISMS-P 2.8.3 시험과 운영 환경 분리 — GitHub Environments API (semi-auto)
# 해당 코드는 레포 파일 내 .env에 GITHUB_TOKEN이 채워져야 정상 실행됨.
# 토큰 발급 후 이 파일에 저장하여 실행할 것.

import requests
import sys
import os
from pathlib import Path
from dotenv import load_dotenv

sys.path.append(str(Path(__file__).resolve().parents[2]))
load_dotenv(Path(__file__).resolve().parents[2] / ".env")
from lib.mapping import to_isms_result


def scan_github_environments(owner_org: str, repo: str, token: str) -> tuple[list[dict], str]:
    url = f"https://api.github.com/repos/{owner_org}/{repo}/environments"
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers).json()
    env_names = [e["name"] for e in resp.get("environments", [])]

    findings = []
    if "production" in env_names and "staging" in env_names:
        findings.append({
            "file": None, "line": None,
            "message": f"prod/staging Environment가 분리되어 등록됨: {env_names}",
            "severity": "INFO",
        })
        status = "PASS"
    else:
        findings.append({
            "file": None, "line": None,
            "message": "production/staging Environment 분리 설정이 확인되지 않음",
            "severity": "MEDIUM",
        })
        status = "FAIL"
    return findings, status


if __name__ == "__main__":
    token = os.environ["GITHUB_TOKEN"]
    org = os.environ.get("GITHUB_ORG", "ISMS-P-Compliance-Gate")
    repo_full = os.environ.get("GITHUB_REPOSITORY", "ISMS-P-Compliance-Gate/ISMS-P-Compliance-Gate")
    repo = repo_full.split("/")[-1]

    findings, status = scan_github_environments(org, repo, token)

    to_isms_result(
        run_id=os.environ.get("GITHUB_RUN_ID", "local-test"),
        control_id="2.8.3", control_name="시험과 운영 환경 분리",
        category="semi-auto", status=status,
        tool="github-environments-api", owner="예원",
        scope="계정/Environment 단위 물리적 분리 여부",
        findings=findings,
        pr_number=int(os.environ["PR_NUMBER"]) if os.environ.get("PR_NUMBER") else None,
    )
