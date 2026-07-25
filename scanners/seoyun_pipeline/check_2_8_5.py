"""
2.8.5 소스 프로그램 관리
main 브랜치가 브랜치 보호 규칙(리뷰 승인, 강제 push 금지, 관리자 강제 적용)으로
통제되고 있는지 GitHub REST API로 확인한다.
"""
import os

from base import GITHUB_API, ISMSRule, finding, github_session, repo_full_name, request_with_retry


class SourceProgramManagementRule(ISMSRule):
    control_id = "2.8.5"
    control_name = "소스 프로그램 관리"
    category = "auto"
    tool = "GitHub REST API (branch protection)"

    def __init__(self):
        super().__init__()
        self.branch = os.getenv("PROTECTED_BRANCH", "main")

    def check(self) -> dict:
        session = github_session()
        repo = repo_full_name()
        url = f"{GITHUB_API}/repos/{repo}/branches/{self.branch}/protection"
        resp = request_with_retry(session, "GET", url)

        if resp.status_code == 404:
            return {
                "status": "FAIL",
                "findings": [finding(
                    f"'{self.branch}' 브랜치에 브랜치 보호 규칙이 설정되어 있지 않습니다. "
                    "PR을 거치지 않고 누구나 직접 push할 수 있는 상태입니다.",
                    severity="HIGH",
                )],
            }
        resp.raise_for_status()
        data = resp.json()
        findings = []

        reviews = data.get("required_pull_request_reviews")
        if not reviews or reviews.get("required_approving_review_count", 0) < 1:
            findings.append(finding(
                f"'{self.branch}' 브랜치: PR 머지 시 최소 리뷰어 승인이 요구되지 않습니다 "
                f"(required_pull_request_reviews: {reviews}). 최소 1인 이상 승인 필수로 설정 필요.",
                severity="HIGH",
            ))

        if not data.get("enforce_admins", {}).get("enabled", False):
            findings.append(finding(
                f"'{self.branch}' 브랜치: 관리자에게는 브랜치 보호 규칙이 강제되지 않습니다 "
                "(enforce_admins=false). 관리자 권한으로 리뷰 없이 머지/강제 push가 가능합니다.",
                severity="MEDIUM",
            ))

        allow_force_pushes = data.get("allow_force_pushes", {}).get("enabled", False)
        if allow_force_pushes:
            findings.append(finding(
                f"'{self.branch}' 브랜치에 강제 push(force push)가 허용되어 있습니다.",
                severity="HIGH",
            ))

        allow_deletions = data.get("allow_deletions", {}).get("enabled", False)
        if allow_deletions:
            findings.append(finding(
                f"'{self.branch}' 브랜치 삭제가 허용되어 있습니다.",
                severity="MEDIUM",
            ))

        status = "FAIL" if findings else "PASS"
        return {"status": status, "findings": findings}


if __name__ == "__main__":
    SourceProgramManagementRule().run()
