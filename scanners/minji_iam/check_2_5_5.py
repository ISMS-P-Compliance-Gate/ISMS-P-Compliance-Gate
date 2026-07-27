import os
import json
import boto3
from lib.mapping import to_isms_result

def check_2_5_5():
    try:
        iam = boto3.client('iam')
        response = iam.list_entities_for_policy(
            PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
        )
        admin_users = response.get('PolicyUsers', [])
        admin_roles = response.get('PolicyRoles', [])
        total_admins = len(admin_users) + len(admin_roles)
        status = "PASS" if total_admins < 5 else "FAIL"
        message = f"ISMS-P 2.5.5(특수 계정 및 권한 관리) - 관리자 권한 보유 주체 {total_admins}개 감지."
    except Exception as e:
        status = "FAIL"
        message = f"ISMS-P 2.5.5(특수 계정 및 권한 관리) - IAM API 호출 실패 ({str(e)})."

    result = to_isms_result(
        run_id="run_latest",
        category="IAM",
        owner="민지",
        control_id="2.5.5",
        control_name="특수 계정 및 권한 관리",
        status=status,
        tool="AWS IAM API",
        findings={"message": message}
    )
    return result

if __name__ == "__main__":
    res = check_2_5_5()
    os.makedirs("results/2_5_5", exist_ok=True)
    with open("results/2_5_5/result.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print("✅ 2.5.5 점검 완료")
