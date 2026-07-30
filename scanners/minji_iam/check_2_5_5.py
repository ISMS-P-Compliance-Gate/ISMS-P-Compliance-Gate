import os
import json
from lib.mapping import to_isms_result

def check_2_5_5():
    findings = {
        "message": "ISMS-P 2.5.5(특수 계정 및 권한 관리) - 본 항목은 관리자/특수 계정의 신청, 승인 및 사용 이력 관리를 수동으로 점검하는 항목입니다.",
        "checklist": [
            "[ ] Root/Administrator 등 특수 계정 사용 시 사전 승인 절차를 거치는가?",
            "[ ] 특수 계정 작업 이력(Audit Log)이 별도로 기록 및 보관되는가?"
        ]
    }
    
    return to_isms_result(
        control_id="2.5.5",
        control_name="특수 계정 및 권한 관리",
        status="MANUAL",
        method="manual",
        tool="N/A",
        findings=findings,
        evidence_path="results/2_5_5/result.json"
    )

if __name__ == "__main__":
    res = check_2_5_5()
    os.makedirs("results/2_5_5", exist_ok=True)
    with open("results/2_5_5/result.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print("✅ 2.5.5 수동 체크리스트 결과 생성 완료")
