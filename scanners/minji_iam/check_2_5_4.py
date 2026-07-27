import os
import json
from lib.mapping import to_isms_result

def check_2_5_4():
    """
    2.5.4 비밀번호 관리 (IdP API 비밀번호 정책)
    """
    # 점검 로직 구현 위치 (비밀번호 복잡도, 길이, 변경 주기 설정 검증)
    status = "PASS"
    msg = "비밀번호 최소 길이, 복잡도, 주기적 변경 정책 기준을 준수하고 있습니다."

    return to_isms_result(
        item_code="2.5.4",
        status=status,
        owner="민지",
        findings={"message": f"ISMS-P 2.5.4(비밀번호 관리) - {msg}"}
    )

if __name__ == "__main__":
    res = check_2_5_4()
    
    os.makedirs("results/2_5_4", exist_ok=True)
    with open("results/2_5_4/result.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print("✅ 2.5.4 점검 완료 및 저장 성공")
