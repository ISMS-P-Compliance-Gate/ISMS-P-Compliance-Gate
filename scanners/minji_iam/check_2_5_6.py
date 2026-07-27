import os
import json
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from lib.mapping import to_isms_result

def check_2_5_6():
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
                    
        if not overprivileged_users:
            status = "PASS"
            msg = "AdministratorAccess 권한이 직접 할당된 미인가 IAM 사용자가 없습니다."
        else:
            status = "FAIL"
            msg = f"과도한 관리자 권한보유 사용자 발견: {', '.join(overprivileged_users)}"
            
    except (BotoCoreError, ClientError) as e:
        status = "FAIL"
        msg = f"AWS IAM 접근권한 검토 중 오류 발생: {str(e)}"

    findings = {
        "message": f"ISMS-P 2.5.6(접근권한 검토) - {msg}"
    }

    return to_isms_result(
        control_id="2.5.6",
        control_name="접근권한 검토",
        status=status,
        method="auto",
        tool="AWS IAM API",
        findings=findings,
        evidence_path="results/2_5_6/result.json"
    )

if __name__ == "__main__":
    res = check_2_5_6()
    
    os.makedirs("results/2_5_6", exist_ok=True)
    with open("results/2_5_6/result.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print("✅ 2.5.6 점검 완료 및 저장 성공")
