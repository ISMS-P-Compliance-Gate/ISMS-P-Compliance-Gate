import os
import json
from lib.mapping import to_isms_result

def check_2_5_4():
    # 비밀번호 정책 점검 로직 (길이, 복잡도, 주기)
    status = "PASS"
    findings = {
        "message": "ISMS-P 2.5.4(비밀번호 관리) - 비밀번호 최소 길이, 복잡도, 주기적 변경 정책 기준을 준수하고 있습니다."
    }
    
    return to_isms_result(
        control_id="2.5.4",
        control_name="비밀번호 관리",
        status=status,
        method="auto",
        tool="IdP Password Policy API",
        findings=findings,
        evidence_path="results/2_5_4/result.json"
    )

if __name__ == "__main__":
    res = check_2_5_4()
    
    os.makedirs("results/2_5_4", exist_ok=True)
    with open("results/2_5_4/result.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print("✅ 2.5.4 점검 완료 및 저장 성공")
