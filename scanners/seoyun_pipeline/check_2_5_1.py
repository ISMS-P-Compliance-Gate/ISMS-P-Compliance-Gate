"""
2.5.1 사용자 계정 관리
조직 구성원의 2FA 설정, Owner/Admin 수, 최근 활동(감사 로그 기준)을
GitHub Organization Members API / Audit Log API로 확인한다.

주의: 조직 멤버 제거 = 접근권한 회수이므로(별도 접근권한 시스템이 없음) PDF에 있던
"계정 해지 후 접근권한 회수 지연" 항목은 이 저장소 구조상 별도로 측정할 데이터가
없어 구현하지 않는다.
"""

#11232

import os
from datetime import datetime, timedelta, timezone

import requests

from base import GITHUB_API, ISMSRule, finding, github_session, org_name, paginate

INACTIVE_DAYS = int(os.getenv("INACTIVE_DAYS", "90"))
ADMIN_THRESHOLD = int(os.getenv("ORG_ADMIN_THRESHOLD", "3"))


class UserAccountManagementRule(ISMSRule):
    control_id = "2.5.1"
    control_name = "사용자 계정 관리"
    category = "auto"
    tool = "GitHub API (org members / audit log)"

    def check(self) -> dict:
        session = github_session()
        org = org_name()

        hard_findings = []  # 2FA 미설정, 90일 이상 비활성 잔류 -> FAIL
        soft_findings = []  # Owner/Admin 과다, 감사로그 접근 불가 -> MANUAL_REQUIRED

        members = list(paginate(session, f"{GITHUB_API}/orgs/{org}/members", params={"per_page": 100}))
        member_logins = {m["login"] for m in members}

        no_2fa = list(paginate(
            session, f"{GITHUB_API}/orgs/{org}/members",
            params={"filter": "2fa_disabled", "per_page": 100},
        ))
        for m in no_2fa:
            hard_findings.append(finding(
                f"'{m['login']}' 계정에 2FA(2단계 인증)가 설정되어 있지 않습니다.",
                severity="HIGH",
            ))

        admins = list(paginate(
            session, f"{GITHUB_API}/orgs/{org}/members",
            params={"role": "admin", "per_page": 100},
        ))
        if len(admins) > ADMIN_THRESHOLD:
            admin_logins = ", ".join(sorted(a["login"] for a in admins))
            soft_findings.append(finding(
                f"조직 Owner/Admin 권한자가 {len(admins)}명으로 임계치({ADMIN_THRESHOLD}명)를 초과합니다: "
                f"{admin_logins}. 최소 권한 원칙에 부합하는지 정책 확인이 필요합니다.",
                severity="MEDIUM",
            ))

        since = (datetime.now(timezone.utc) - timedelta(days=INACTIVE_DAYS)).strftime("%Y-%m-%d")
        try:
            events = list(paginate(
                session, f"{GITHUB_API}/orgs/{org}/audit-log",
                params={"phrase": f"created:>{since}", "per_page": 100},
            ))
            active_actors = {e.get("actor") for e in events if e.get("actor")}
            inactive_members = member_logins - active_actors
            for login in sorted(inactive_members):
                hard_findings.append(finding(
                    f"'{login}' 계정이 최근 {INACTIVE_DAYS}일간 감사 로그에 활동 이력이 없는데도 "
                    "조직에 여전히 소속되어 있습니다. 퇴직/휴면 계정 여부 확인이 필요합니다.",
                    severity="HIGH",
                ))
        except requests.HTTPError as exc:
            # audit-log API는 GitHub Enterprise + org owner 토큰이 필요해 접근 불가일 수 있음
            soft_findings.append(finding(
                f"감사 로그(audit-log) API에 접근할 수 없어 계정 비활성 여부를 자동으로 판단하지 못했습니다 "
                f"({exc.response.status_code if exc.response is not None else exc}). 수동 확인이 필요합니다.",
                severity="LOW",
            ))

        if hard_findings:
            status = "FAIL"
        elif soft_findings:
            status = "MANUAL_REQUIRED"
        else:
            status = "PASS"

        return {"status": status, "findings": hard_findings + soft_findings}


if __name__ == "__main__":
    UserAccountManagementRule().run()
