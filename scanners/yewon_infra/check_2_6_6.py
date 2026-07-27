# ISMS-P 2.6.6 원격접근 통제 — 원안 미설계 항목, checklist 형식

# [실행 방법]
# python(혹은 python3) scanners/yewon_infra/check_2_6_6.py
# ls results/2_6_6/

import sys
import os
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))
from lib.mapping import to_isms_result

if __name__ == "__main__":
    to_isms_result(
        run_id=os.environ.get("GITHUB_RUN_ID", "local-test"),
        control_id="2.6.6", control_name="원격접근 통제",
        category="checklist", status="MANUAL_REQUIRED",
        tool="manual", owner="예원",
        checklist_items=[
            "원격 접속(VPN)은 승인된 사용자만 사용하고 있습니까?",
            "원격 접속 시 다중 인증(MFA)이 적용되고 있습니까?",
            "원격 접속 로그가 최소 90일 이상 보관되고 있습니까?",
            "퇴사/직무변경 시 원격접속 권한이 즉시 회수되고 있습니까?",
        ],
    )
