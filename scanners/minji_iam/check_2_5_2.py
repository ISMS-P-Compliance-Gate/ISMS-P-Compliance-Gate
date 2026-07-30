import os
import json
from lib.mapping import to_isms_result

def check_2_5_2():
    findings = {
        "message": "ISMS-P 2.5.2(사용자 계정 관리) - 본 항목은 계정 등록, 신청, 승인 프로세스 및 휴면 계정 관리를 수동으로 점검하는 항목입니다.",
        "checklist": [
            "[ ] 사용자 계정 등록/발급 시 정식 승인 절차를 거쳤는가?",
            "[ ] 장기 미사용 계정(휴면 계정)에 대한 주기적인 복구/잠금/삭제 조치가 이루어지는가?"
        ]
    }
    
    return to_isms_result(
        control_id="2.5.2",
        control_name="사용자 계정 관리",
        status="MANUAL",
        method="manual",
        tool="N/A",
        findings=findings,
        evidence_path="results/2_5_2/result.json"
    )

if __name__ == "__main__":
    res = check_2_5_2()
    os.makedirs("results/2_5_2", exist_ok=True)
    with open("results/2_5_2/result.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print("✅ 2.5.2 수동 체크리스트 결과 생성 완료")
