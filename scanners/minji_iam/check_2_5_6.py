import os
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2]))
from lib.mapping import to_isms_result

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def check_2_5_6(run_id: str = "local-test"):
    findings = []
    try:
        iam = boto3.client("iam")
        users = iam.list_users()
        overprivileged_users = []

        for user in users.get("Users", []):
            username = user["UserName"]
            policies = iam.list_attached_user_policies(UserName=username)
            for p in policies.get("AttachedPolicies", []):
                if p["PolicyName"] == "AdministratorAccess":
                    overprivileged_users.append(username)

        if overprivileged_users:
            status = "FAIL"
            for username in overprivileged_users:
                findings.append({
                    "message": f"AdministratorAccess 권한이 직접 할당된 사용자 발견: {username}",
                    "severity": "HIGH",
                })
        else:
            status = "PASS"
            findings.append({
                "message": "AdministratorAccess 권한이 직접 할당된 미인가 IAM 사용자가 없습니다.",
                "severity": "INFO",
            })

    except (BotoCoreError, ClientError) as e:
        status = "ERROR"
        findings.append({
            "message": f"AWS IAM 접근권한 검토 중 오류 발생: {str(e)}",
            "severity": "HIGH",
        })

    return to_isms_result(
        run_id=run_id,
        control_id="2.5.6",
        control_name="접근권한 검토",
        category="auto",
        status=status,
        tool="AWS IAM API",
        owner="민지",
        findings=findings,
    )


if __name__ == "__main__":
    RUN_ID = os.getenv("GITHUB_RUN_ID", "local-test")
    res = check_2_5_6(run_id=RUN_ID)
    print(f"2.5.6 점검 완료: {res['status']} (저장 위치: {res['evidence_path']})")
