import os
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2]))
from lib.mapping import to_isms_result

import requests


def check_2_5_3(okta_domain: str, okta_token: str, run_id: str = "local-test"):
    headers = {
        "Authorization": f"SSWS {okta_token}",
        "Accept": "application/json",
    }
    url = f"https://{okta_domain}/api/v1/policies?type=MFA_ENROLL"

    findings = []
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        policies = response.json()

        enforced = any(
            p.get("status") == "ACTIVE"
            and p.get("conditions", {}).get("people", {}).get("groups", {}).get("include")
            for p in policies
        )

        if enforced:
            status = "PASS"
            findings.append({
                "message": "전체 사용자 그룹 대상 MFA 강제 적용 정책이 활성화되어 있습니다.",
                "severity": "INFO",
            })
        else:
            status = "FAIL"
            findings.append({
                "message": "전체 사용자 대상으로 활성화된 MFA 강제 정책을 찾을 수 없습니다.",
                "severity": "HIGH",
            })

    except requests.exceptions.RequestException as e:
        status = "ERROR"
        findings.append({
            "message": f"Okta API 호출 중 오류 발생: {str(e)}",
            "severity": "HIGH",
        })

    return to_isms_result(
        run_id=run_id,
        control_id="2.5.3",
        control_name="사용자 인증",
        category="auto",
        status=status,
        tool="Okta Policies API",
        owner="민지",
        findings=findings,
    )


if __name__ == "__main__":
    OKTA_DOMAIN = os.getenv("OKTA_DOMAIN", "your-org.okta.com")
    OKTA_TOKEN = os.getenv("OKTA_API_TOKEN", "")
    RUN_ID = os.getenv("GITHUB_RUN_ID", "local-test")

    res = check_2_5_3(OKTA_DOMAIN, OKTA_TOKEN, run_id=RUN_ID)
    print(f"2.5.3 점검 완료: {res['status']} (저장 위치: {res['evidence_path']})")
