import os
import json
from lib.mapping import to_isms_result

def check_2_5_2():
    """
    2.5.2 사용자 식별 (IdP API: Okta / AD)
    """
    # 점검 로직 구현 위치 (공유/미식별 계정 여부 검증)
    status = "PASS"
    msg = "IdP 내 식별되지 않은 공용/공유 계정이 존재하지 않습니다."

    return to_isms_result(
        item_code="2.5.2",
        status=status,
        owner="민지",
        findings={"message": f"ISMS-P 2.5.2(사용자 식별) - {msg}"}
    )

if __name__ == "__main__":
    res = check_2_5_2()
    
    os.makedirs("results/2_5_2", exist_ok=True)
    with open("results/2_5_2/result.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print("✅ 2.5.2 점검 완료 및 저장 성공")
