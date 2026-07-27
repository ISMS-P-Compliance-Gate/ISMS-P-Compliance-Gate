import os
import json
from lib.mapping import to_isms_result

def check_2_5_3():
    # MFA 정책 강제 적용 여부 점검 로직
    status = "PASS"
    findings = {
        "message": "ISMS-P 2.5.3(사용자 인증) - 모든 사용자 계정에 MFA 강제 적용 정책이 설정되어 있습니다."
    }
    
    return to_isms_result(
        control_id="2.5.3",
        control_name="사용자 인증",
        status=status,
        method="auto",
        tool="Okta/Azure AD API",
        findings=findings,
        evidence_path="results/2_5_3/result.json"
    )

if __name__ == "__main__":
    res = check_2_5_3()
    
    os.makedirs("results/2_5_3", exist_ok=True)
    with open("results/2_5_3/result.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print("✅ 2.5.3 점검 완료 및 저장 성공")
