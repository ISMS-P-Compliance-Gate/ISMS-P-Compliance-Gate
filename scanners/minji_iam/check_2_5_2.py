import os
import re
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2]))
from lib.mapping import to_isms_result

import requests

# 공용/공유 계정으로 의심되는 로그인 패턴 (조직 정책에 맞게 조정)
SHARED_ACCOUNT_PATTERN = re.compile(
    r"(shared|common|test|temp|admin\d*|공용|공유|테스트)", re.IGNORECASE
)


def check_2_5_2(okta_domain: str, okta_token: str, run_id: str = "local-test"):
    headers = {
        "Authorization": f"SSWS {okta_token}",
        "Accept": "application/json",
    }
    url = f"https://{okta_domain}/api/v1/users?filter=status eq \"ACTIVE\""

    findings = []
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        users = response.json()

        suspected = [
            u["profile"]["login"]
            for u in users
            if SHARED_ACCOUNT_PATTERN.search(u.get("profile", {}).get("login", ""))
        ]

        if suspected:
            for login in suspected:
                findings.append({
                    "message": f"공용/공유 계정으로 의심되는 IdP 계정 발견: {login}",
                    "severity": "MEDIUM",
                })
            status = "FAIL"
        else:
            status = "PASS"
            findings.append({
                "message": "IdP 내 식별되지 않은 공용/공유 계정 패턴이 발견되지 않았습니다.",
                "severity": "INFO",
            })

    except requests.exceptions.RequestException as e:
        status = "ERROR"
        findings.append({
            "message": f"Okta API 호출 중 오류 발생: {str(e)}",
            "severity": "HIGH",
        })

    return to_isms_result(
        run_id=run_id,
        control_id="2.5.2",
        control_name="사용자 식별",
        category="auto",
        status=status,
        tool="Okta Users API",
        owner="민지",
        findings=findings,
    )


if __name__ == "__main__":
    OKTA_DOMAIN = os.getenv("OKTA_DOMAIN", "your-org.okta.com")
    OKTA_TOKEN = os.getenv("OKTA_API_TOKEN", "")
    RUN_ID = os.getenv("GITHUB_RUN_ID", "local-test")

    res = check_2_5_2(OKTA_DOMAIN, OKTA_TOKEN, run_id=RUN_ID)
    print(f"2.5.2 점검 완료: {res['status']} (저장 위치: {res['evidence_path']})")
