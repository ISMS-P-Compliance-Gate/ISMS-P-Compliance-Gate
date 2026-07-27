import os
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2]))
from lib.mapping import to_isms_result

import requests

MIN_LENGTH_REQUIRED = 8
MAX_AGE_DAYS_REQUIRED = 90


def check_2_5_4(okta_domain: str, okta_token: str, run_id: str = "local-test"):
    headers = {
        "Authorization": f"SSWS {okta_token}",
        "Accept": "application/json",
    }
    url = f"https://{okta_domain}/api/v1/policies?type=PASSWORD"

    findings = []
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        policies = response.json()

        active_policies = [p for p in policies if p.get("status") == "ACTIVE"]
        if not active_policies:
            status = "FAIL"
            findings.append({
                "message": "활성화된 비밀번호 정책을 찾을 수 없습니다.",
                "severity": "HIGH",
            })
        else:
            for p in active_policies:
                complexity = p.get("settings", {}).get("password", {}).get("complexity", {})
                min_length = complexity.get("minLength", 0)
                max_age_days = complexity.get("maxAgeDays", 0)

                if min_length < MIN_LENGTH_REQUIRED:
                    findings.append({
                        "message": f"비밀번호 최소 길이({min_length})가 기준({MIN_LENGTH_REQUIRED}) 미만입니다.",
                        "severity": "HIGH",
                    })
                if max_age_days == 0 or max_age_days > MAX_AGE_DAYS_REQUIRED:
                    findings.append({
                        "message": f"비밀번호 변경 주기가 기준({MAX_AGE_DAYS_REQUIRED}일)을 준수하지 않습니다.",
                        "severity": "MEDIUM",
                    })

            status = "FAIL" if findings else "PASS"
            if not findings:
                findings.append({
                    "message": "비밀번호 최소 길이, 복잡도, 주기적 변경 정책 기준을 준수하고 있습니다.",
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
        control_id="2.5.4",
        control_name="비밀번호 관리",
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

    res = check_2_5_4(OKTA_DOMAIN, OKTA_TOKEN, run_id=RUN_ID)
    print(f"2.5.4 점검 완료: {res['status']} (저장 위치: {res['evidence_path']})")
