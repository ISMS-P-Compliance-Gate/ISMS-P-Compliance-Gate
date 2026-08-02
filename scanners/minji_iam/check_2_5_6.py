import sys
import os
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))
from lib.mapping import to_isms_result

if __name__ == "__main__":
    to_isms_result(
        run_id=os.environ.get("GITHUB_RUN_ID", "local-test"),
        control_id="2.5.6",
        control_name="접근권한 검토",
        category="checklist",
        status="MANUAL_REQUIRED",
        tool="manual",
        owner="민지",
        checklist_items=[
            "반기/연 1회 이상 전체 사용자 및 관리자 접근권한 재검토를 수행하고 있습니까?",
            "권한 오남용 또는 불필요한 권한 회수 결과 보고서가 존재합니까?",
        ],
    )
    print("✅ 2.5.6 수동 체크리스트 결과 생성 완료")
