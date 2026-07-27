# ISMS-P 2.6.7 인터넷 접속 통제 — 원안 미설계 항목, checklist 형식

# [실행 방법]
# python (혹은 python3) scanners/yewon_infra/check_2_6_7.py
# ls results/2_6_7/

import sys
import os
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))
from lib.mapping import to_isms_result

if __name__ == "__main__":
    to_isms_result(
        run_id=os.environ.get("GITHUB_RUN_ID", "local-test"),
        control_id="2.6.7", control_name="인터넷 접속 통제",
        category="checklist", status="MANUAL_REQUIRED",
        tool="manual", owner="예원",
        checklist_items=[
            "업무용 단말의 인터넷 접속은 허용된 목적지로만 제한되고 있습니까?",
            "인터넷 접속 로그가 정기적으로 점검되고 있습니까?",
        ],
    )
