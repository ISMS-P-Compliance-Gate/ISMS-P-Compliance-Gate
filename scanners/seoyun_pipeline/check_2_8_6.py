"""
2.8.6 운영환경 이관
production environment에 배포 승인(required reviewers) 규칙이 걸려있는지,
배포 이력이 추적되는지 GitHub Actions Environments/Deployments API로 확인한다.
"""
import os

from base import GITHUB_API, ISMSRule, finding, github_session, paginate, repo_full_name, request_with_retry

PROD_ENV_NAME = os.getenv("PROD_ENV_NAME", "production")


class ProductionDeploymentRule(ISMSRule):
    control_id = "2.8.6"
    control_name = "운영환경 이관"
    category = "auto"
    tool = "GitHub Actions API (environments / deployments)"

    def check(self) -> dict:
        session = github_session()
        repo = repo_full_name()

        hard_findings = []
        soft_findings = []

        env_resp = request_with_retry(session, "GET", f"{GITHUB_API}/repos/{repo}/environments/{PROD_ENV_NAME}")
        if env_resp.status_code == 404:
            hard_findings.append(finding(
                f"'{PROD_ENV_NAME}' environment가 정의되어 있지 않습니다. "
                "운영 배포에 대한 승인/보호 규칙을 적용할 대상 자체가 없습니다.",
                severity="HIGH",
            ))
        else:
            env_resp.raise_for_status()
            env = env_resp.json()
            rules = env.get("protection_rules", [])
            has_required_reviewers = any(r.get("type") == "required_reviewers" for r in rules)
            if not has_required_reviewers:
                hard_findings.append(finding(
                    f"'{PROD_ENV_NAME}' environment에 배포 승인자(required reviewers)가 설정되어 있지 않아 "
                    "승인 없이 자동으로 운영 배포가 이루어집니다.",
                    severity="HIGH",
                ))

        deployments = list(paginate(
            session, f"{GITHUB_API}/repos/{repo}/deployments",
            params={"environment": PROD_ENV_NAME, "per_page": 100},
        ))
        if not deployments:
            soft_findings.append(finding(
                f"'{PROD_ENV_NAME}' environment로 기록된 배포 이력이 없습니다. "
                "실제 운영 배포가 이 API를 통해 추적되고 있는지 수동 확인이 필요합니다.",
                severity="LOW",
            ))
        else:
            for dep in deployments[:20]:
                status_resp = request_with_retry(
                    session, "GET",
                    f"{GITHUB_API}/repos/{repo}/deployments/{dep['id']}/statuses",
                    params={"per_page": 1},
                )
                status_resp.raise_for_status()
                if not status_resp.json():
                    hard_findings.append(finding(
                        f"배포 #{dep['id']} (created_at: {dep.get('created_at')})에 대한 상태(status) "
                        "기록이 없어 배포 성공/실패 여부가 추적되지 않습니다.",
                        severity="MEDIUM",
                    ))

        # 배포 실패 시 롤백 절차는 API로 확인할 근거 데이터가 없어 이 스캐너의 점검 범위에서
        # 제외한다(PDF 기준 별도 체크리스트 항목으로 팀 문서에 남겨두는 것을 권장).
        if hard_findings:
            status = "FAIL"
        elif soft_findings:
            status = "MANUAL_REQUIRED"
        else:
            status = "PASS"

        return {"status": status, "findings": hard_findings + soft_findings}


if __name__ == "__main__":
    ProductionDeploymentRule().run()
