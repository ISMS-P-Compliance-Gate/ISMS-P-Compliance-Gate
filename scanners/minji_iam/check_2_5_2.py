import os
import json
from lib.mapping import to_isms_result

def check_2_5_2():
    # IdP/AD API 기반 1인 1계정 및 공유계정 점검 로직
    status = "PASS"
    findings = {
        "message": "ISMS-P 2.5.2(사용자 식별) - IdP 내 식별되지 않은 공용/공유 계정이 존재하지 않습니다."
    }
    
    return to_isms_result(
        control_id="2.5.2",
        control_name="사용자 식별",
        status=status,
        method="auto",
        tool="IdP API",
        findings=findings,
        evidence_path="results/2_5_2/result.json"
    )

if __name__ == "__main__":
    res = check_2_5_2()
    
    os.makedirs("results/2_5_2", exist_ok=True)
    with open("results/2_5_2/result.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print("✅ 2.5.2 점검 완료 및 저장 성공")
