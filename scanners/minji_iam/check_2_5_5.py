import sys
import os
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))
from lib.mapping import to_isms_result

if __name__ == "__main__":
    to_isms_result(
        run_id=os.environ.get("GITHUB_RUN_ID", "local-test"),
        control_id="2.5.5",
        control_name="특수 계정 및 권한 관리",
        category="checklist",
        status="MANUAL_REQUIRED",
        tool="manual",
        owner="민지",
        checklist_items=[
            "Root/Administrator 등 특수 계정 사용 시 사전 승인 절차를 거치고 있습니까?",
            "특수 계정 작업 이력(Audit Log)이 별도로 기록 및 보관되고 있습니까?",
        ],
    )
    print("✅ 2.5.5 수동 체크리스트 결과 생성 완료")
    
