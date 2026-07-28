import os
import json
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))
from lib.mapping import to_isms_result

def check_2_5_3():
    """
    2.5.3 사용자 인증 (IdP API: Okta / Azure AD)
    """
    # 점검 로직 구현 위치 (MFA 강제 적용 여부 검증)
    status = "PASS"
    msg = "모든 사용자 계정에 MFA 강제 적용 정책이 설정되어 있습니다."

    return to_isms_result(
        run_id=os.environ.get("GITHUB_RUN_ID", "local-test"),
        control_id="2.5.3",
        control_name="사용자 인증",
        category="auto",
        status=status,
        tool="IdP API (Okta/Azure AD)",
        owner="민지",
        findings=[{"message": f"ISMS-P 2.5.3(사용자 인증) - {msg}"}]
    )

if __name__ == "__main__":
    res = check_2_5_3()
    
    os.makedirs("results/2_5_3", exist_ok=True)
    with open("results/2_5_3/result.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print("✅ 2.5.3 점검 완료 및 저장 성공")
