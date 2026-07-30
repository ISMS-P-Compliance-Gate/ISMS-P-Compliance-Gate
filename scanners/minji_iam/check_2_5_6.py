import os
import json
from lib.mapping import to_isms_result

def check_2_5_6():
    findings = {
        "message": "ISMS-P 2.5.6(접근권한 검토) - 본 항목은 정보시스템 및 개인정보처리시스템 접근권한의 정기적 검토 현황을 수동 점검하는 항목입니다.",
        "checklist": [
            "[ ] 반기/연 1회 이상 전체 사용자 및 관리자 접근권한 재검토를 수행하는가?",
            "[ ] 권한 오남용 또는 불필요한 권한 회수 결과 보고서가 존재하는가?"
        ]
    }
    
    return to_isms_result(
        control_id="2.5.6",
        control_name="접근권한 검토",
        status="MANUAL",
        method="manual",
        tool="N/A",
        findings=findings,
        evidence_path="results/2_5_6/result.json"
    )

if __name__ == "__main__":
    res = check_2_5_6()
    os.makedirs("results/2_5_6", exist_ok=True)
    with open("results/2_5_6/result.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print("✅ 2.5.6 수동 체크리스트 결과 생성 완료")
