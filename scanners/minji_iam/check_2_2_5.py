import os
import json
from lib.mapping import to_isms_result

def check_2_2_5():
    # 복잡한 API 호출이나 에러가 날 수 있는 로직은 모두 제거합니다.
    findings = {
        "message": "ISMS-P 2.2.5(퇴직 및 직무변경 관리) - 본 항목은 담당자가 GitHub/IAM 권한 목록을 직접 확인하여 점검하는 수동 체크리스트 대상입니다.",
        "checklist": [
            "[ ] 퇴직자 및 직무 변경자의 계정이 즉시 권한 해제/삭제 되었는가?",
            "[ ] 공용 계정 및 dangling 권한이 존재하지 않는가?"
        ]
    }
    
    result = to_isms_result(
        control_id="2.2.5",
        control_name="퇴직 및 직무변경 관리",
        status="MANUAL",  # 프로젝트 공통 포맷에 따라 "MANUAL" 또는 "CHECKLIST" 등으로 지정
        method="manual",
        tool="N/A",
        findings=findings,
        evidence_path="results/2_2_5/result.json"
    )
    return result

if __name__ == "__main__":
    res = check_2_2_5()
    
    os.makedirs("results/2_2_5", exist_ok=True)
    with open("results/2_2_5/result.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print("✅ 2.2.5 수동 체크리스트 결과 생성 완료")
