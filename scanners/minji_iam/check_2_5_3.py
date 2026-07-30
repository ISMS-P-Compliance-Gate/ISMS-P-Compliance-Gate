import os
import json
from lib.mapping import to_isms_result

def check_2_5_3():
    findings = {
        "message": "ISMS-P 2.5.3(사용자 권한 관리) - 본 항목은 최소 권한 부여 원칙 및 주기적 권한 검토 현황을 수동으로 확인하는 항목입니다.",
        "checklist": [
            "[ ] 업무에 필요한 최소한의 권한(Least Privilege)만 부여되어 있는가?",
            "[ ] 정기적으로 사용자 권한 부여 현황을 재검토하고 있는가?"
        ]
    }
    
    return to_isms_result(
        control_id="2.5.3",
        control_name="사용자 권한 관리",
        status="MANUAL",
        method="manual",
        tool="N/A",
        findings=findings,
        evidence_path="results/2_5_3/result.json"
    )

if __name__ == "__main__":
    res = check_2_5_3()
    os.makedirs("results/2_5_3", exist_ok=True)
    with open("results/2_5_3/result.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print("✅ 2.5.3 수동 체크리스트 결과 생성 완료")
