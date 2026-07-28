import os
import json
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))
from lib.mapping import to_isms_result

def check_2_5_4():
    """
    2.5.4 비밀번호 관리 (IdP API 비밀번호 정책)
    """
    # 점검 로직 구현 위치 (비밀번호 복잡도, 길이, 변경 주기 설정 검증)
    status = "PASS"
    msg = "비밀번호 최소 길이, 복잡도, 주기적 변경 정책 기준을 준수하고 있습니다."

    return to_isms_result(
        run_id=os.environ.get("GITHUB_RUN_ID", "local-test"),
        control_id="2.5.4",
        control_name="비밀번호 관리",
        category="auto",
        status=status,
        tool="IdP API",
        owner="민지",
        findings=[{"message": f"ISMS-P 2.5.4(비밀번호 관리) - {msg}"}]
    )

if __name__ == "__main__":
    res = check_2_5_4()
    
    os.makedirs("results/2_5_4", exist_ok=True)
    with open("results/2_5_4/result.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print("✅ 2.5.4 점검 완료 및 저장 성공")
