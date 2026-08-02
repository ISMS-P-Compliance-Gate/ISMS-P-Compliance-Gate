import sys
import os
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))  # 누락: ModuleNotFoundError 원인
from lib.mapping import to_isms_result

if __name__ == "__main__":
    to_isms_result(
        run_id=os.environ.get("GITHUB_RUN_ID", "local-test"),  # 누락: 필수 파라미터
        control_id="2.5.3",
        control_name="사용자 권한 관리",
        category="checklist",       # method="manual" → category
        status="MANUAL_REQUIRED",   # "MANUAL" → enum 값 아님
        tool="manual",              # "N/A" → 표기 통일
        owner="민지",                # 누락: 필수 파라미터
        checklist_items=[           # findings(dict) → checklist_items(list)
            "업무에 필요한 최소한의 권한(Least Privilege)만 부여되어 있습니까?",
            "정기적으로 사용자 권한 부여 현황을 재검토하고 있습니까?",
        ],
    )
    print("✅ 2.5.3 수동 체크리스트 결과 생성 완료")
