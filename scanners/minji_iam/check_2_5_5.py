import os
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2]))
from lib.mapping import to_isms_result

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def check_2_5_5(run_id: str = "local-test"):
    findings = []
    try:
        iam = boto3.client("iam")
        summary = iam.get_account_summary()
        root_mfa = summary.get("SummaryMap", {}).get("AccountMFAEnabled", 0)

        if root_mfa == 1:
            status = "PASS"
            findings.append({
                "message": "AWS Root 계정에 MFA가 정상 적용되어 있습니다.",
                "severity": "INFO",
            })
        else:
            status = "FAIL"
            findings.append({
                "message": "AWS Root 계정에 MFA가 설정되어 있지 않습니다.",
                "severity": "HIGH",
            })

    except (BotoCoreError, ClientError) as e:
        status = "ERROR"
        findings.append({
            "message": f"AWS IAM API 호출 실패: {str(e)}",
            "severity": "HIGH",
        })

    return to_isms_result(
        run_id=run_id,
        control_id="2.5.5",
        control_name="특수 계정 및 권한 관리",
        category="auto",
        status=status,
        tool="AWS IAM API",
        owner="민지",
        findings=findings,
    )


if __name__ == "__main__":
    RUN_ID = os.getenv("GITHUB_RUN_ID", "local-test")
    res = check_2_5_5(run_id=RUN_ID)
    print(f"2.5.5 점검 완료: {res['status']} (저장 위치: {res['evidence_path']})")
