import os
import json
from lib.mapping import to_isms_result

def check_2_5_4():
    findings = {
        "message": "ISMS-P 2.5.4(비밀번호 관리) - 본 항목은 비밀번호 설정 복잡도 및 수명 주기 정책 이행 여부를 수동으로 확인하는 항목입니다.",
        "checklist": [
            "[ ] 비밀번호 복잡도(영문, 숫자, 특수문자 조합 등)가 설정되어 있는가?",
            "[ ] 비밀번호 변경 주기 및 최근 비밀번호 재사용 제한이 적용되어 있는가?"
        ]
    }
    
    return to_isms_result(
        control_id="2.5.4",
        control_name="비밀번호 관리",
        status="MANUAL",
        method="manual",
        tool="N/A",
        findings=findings,
        evidence_path="results/2_5_4/result.json"
    )

if __name__ == "__main__":
    res = check_2_5_4()
    os.makedirs("results/2_5_4", exist_ok=True)
    with open("results/2_5_4/result.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print("✅ 2.5.4 수동 체크리스트 결과 생성 완료")
