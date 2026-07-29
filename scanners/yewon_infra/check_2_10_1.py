# ISMS-P 2.10.1 보안시스템 운영 - GuardDuty/WAF 활성화 상태 확인
"""
[임시 조치]
AWS 계정이 Free Plan 상태라 GuardDuty API 접근이 막혀있어(SubscriptionRequiredException) 자동 조회가 불가능함.
따라서, auto가 아닌 checklist로 낮춰서 처리한다. 
만약 Paid Plan 전환을 결정하면, 1) 이 파일을 다시 category="auto"로 되돌리고,
2) boto3로 GuardDuty/WAF를 직접 조회하는 코드로 바꾸면 된다.

[boto3로 GuardDuty/WAF를 직접 조회하는 코드]
# ISMS-P 2.10.1 보안시스템 운영 — AWS GuardDuty, WAFv2 활성화 상태 확인

import boto3
import sys
import os
from pathlib import Path
from dotenv import load_dotenv

sys.path.append(str(Path(__file__).resolve().parents[2]))
load_dotenv(Path(__file__).resolve().parents[2] / ".env")
from lib.mapping import to_isms_result
from severity import classify_service_disabled


def scan_security_systems() -> list[dict]:
    findings = []
    gd = boto3.client("guardduty")
    detectors = gd.list_detectors()["DetectorIds"]
    is_enabled = bool(detectors) and gd.get_detector(DetectorId=detectors[0])["Status"] == "ENABLED"
    severity = classify_service_disabled(is_enabled)
    if severity:
        findings.append({"file": None, "line": None, "message": "GuardDuty가 비활성화되어 있음", "severity": severity})

    waf = boto3.client("wafv2")
    has_acl = bool(waf.list_web_acls(Scope="REGIONAL")["WebACLs"])
    severity = classify_service_disabled(has_acl)
    if severity:
        findings.append({"file": None, "line": None, "message": "WAF WebACL이 설정되어 있지 않음", "severity": severity})

    return findings


if __name__ == "__main__":
    findings = scan_security_systems()
    to_isms_result(
        run_id=os.environ.get("GITHUB_RUN_ID", "local-test"),
        control_id="2.10.1", control_name="보안시스템 운영",
        category="auto", status="FAIL" if findings else "PASS",
        tool="boto3-guardduty-wafv2", owner="예원", findings=findings,
    )


"""

import sys
import os
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))
from lib.mapping import to_isms_result

if __name__ == "__main__":
    to_isms_result(
        run_id=os.environ.get("GITHUB_RUN_ID", "local-test"),
        control_id="2.10.1",
        control_name="보안시스템 운영",
        category="checklist",
        status="MANUAL_REQUIRED",
        tool="manual",
        owner="예원",
        checklist_items=[
            "GuardDuty가 활성화되어 있습니까? (AWS 계정이 Free Plan이라 자동 점검 불가, Paid Plan 전환 후 auto로 전환 예정)",
            "WAF WebACL이 설정되어 있습니까?",
        ],
    )
    
