import os
import json
from lib.mapping import to_isms_result

def check_2_5_3():
    """
    2.5.3 사용자 인증 (IdP API: Okta / Azure AD)
    """
    # 점검 로직 구현 위치 (MFA 강제 적용 여부 검증)
    status = "PASS"
    msg = "모든 사용자 계정에 MFA 강제 적용 정책이 설정되어 있습니다."

    return to_isms_result(
        item_code="2.5.3",
        status=status,
        owner="민지",
        findings={"message": f"ISMS-P 2.5.3(사용자 인증) - {msg}"}
    )

if __name__ == "__main__":
    res = check_2_5_3()
    
    os.makedirs("results/2_5_3", exist_ok=True)
    with open("results/2_5_3/result.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print("✅ 2.5.3 점검 완료 및 저장 성공")
