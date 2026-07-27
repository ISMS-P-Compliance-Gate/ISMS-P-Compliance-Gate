import os
import json
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from lib.mapping import to_isms_result

def check_2_5_5():
    """
    2.5.5 특수 계정 및 권한 관리 (AWS IAM API)
    """
    try:
        iam = boto3.client("iam")
        summary = iam.get_account_summary()
        root_mfa = summary.get("SummaryMap", {}).get("AccountMFAEnabled", 0)
        
        if root_mfa == 1:
            status = "PASS"
            msg = "AWS Root 계정에 MFA가 정상 적용되어 있습니다."
        else:
            status = "FAIL"
            msg = "AWS Root 계정에 MFA가 설정되어 있지 않습니다."
    except (BotoCoreError, ClientError) as e:
        status = "FAIL"
        msg = f"AWS IAM API 호출 실패: {str(e)}"

    return to_isms_result(
        item_code="2.5.5",
        status=status,
        owner="민지",
        findings={"message": f"ISMS-P 2.5.5(특수 계정 및 권한 관리) - {msg}"}
    )

if __name__ == "__main__":
    res = check_2_5_5()
    
    os.makedirs("results/2_5_5", exist_ok=True)
    with open("results/2_5_5/result.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print("✅ 2.5.5 점검 완료 및 저장 성공")
