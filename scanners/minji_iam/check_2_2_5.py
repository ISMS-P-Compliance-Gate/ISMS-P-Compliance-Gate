import os
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2]))
from lib.mapping import to_isms_result

import requests


def check_2_2_5(org_name: str, github_token: str, run_id: str = "local-test"):
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github+json",
    }
    url = f"https://api.github.com/orgs/{org_name}/audit-log?phrase=action:org.remove_member"

    findings = []
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        removal_events = response.json()

        # org.remove_member 이벤트가 존재하면, 해당 인원의 권한이 실제로
        # 회수되었는지는 자동으로 단정할 수 없으므로 사람이 대조해야 함 (semi-auto)
        if removal_events:
            for event in removal_events:
                findings.append({
                    "message": f"조직 제거 이벤트 감지: {event.get('user', '알수없음')} "
                                f"({event.get('created_at', '시각 미상')}) - 잔여 권한 여부 수동 확인 필요",
                    "severity": "MEDIUM",
                })
            status = "MANUAL_REQUIRED"
        else:
            status = "PASS"

    except requests.exceptions.RequestException as e:
        status = "ERROR"
        findings.append({
            "message": f"GitHub API 호출 중 오류 발생: {str(e)}",
            "severity": "HIGH",
        })

    return to_isms_result(
        run_id=run_id,
        control_id="2.2.5",
        control_name="퇴직 및 직무변경 관리",
        category="semi-auto",
        status=status,
        tool="GitHub Audit Log API",
        owner="민지",
        findings=findings,
        scope="GitHub 조직 제거(org.remove_member) 이벤트를 자동 수집하고, "
              "실제 잔여 권한 회수 여부는 담당자가 수동으로 대조 확인함",
    )


if __name__ == "__main__":
    TOKEN = os.getenv("GITHUB_TOKEN", "")
    ORG = os.getenv("GITHUB_ORG", "your-org")
    RUN_ID = os.getenv("GITHUB_RUN_ID", "local-test")

    res = check_2_2_5(ORG, TOKEN, run_id=RUN_ID)
    print(f"2.2.5 점검 완료: {res['status']} (저장 위치: {res['evidence_path']})")
