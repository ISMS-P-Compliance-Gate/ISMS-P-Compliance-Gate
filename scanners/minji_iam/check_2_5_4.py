import sys
import os
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))
from lib.mapping import to_isms_result

if __name__ == "__main__":
    to_isms_result(
        run_id=os.environ.get("GITHUB_RUN_ID", "local-test"),
        control_id="2.5.4",
        control_name="비밀번호 관리",
        category="checklist",
        status="MANUAL_REQUIRED",
        tool="manual",
        owner="민지",
        checklist_items=[
            "비밀번호 복잡도(영문, 숫자, 특수문자 조합 등)가 설정되어 있습니까?",
            "비밀번호 변경 주기 및 최근 비밀번호 재사용 제한이 적용되어 있습니까?",
        ],
    )
    print("✅ 2.5.4 수동 체크리스트 결과 생성 완료")
