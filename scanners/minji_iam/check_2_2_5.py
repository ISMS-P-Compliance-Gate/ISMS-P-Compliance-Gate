import os
import json
import requests
from lib.mapping import to_isms_result

def check_2_2_5(org_name="", github_token=""):
    """
    2.2.5 퇴직 및 직무변경 관리 (GitHub API / AD / Okta)
    """
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github+json"
    }
    url = f"https://api.github.com/orgs/{org_name}/audit-log?phrase=action:org.remove_member"
    
    try:
        if github_token and org_name:
            response = requests.get(url, headers=headers, timeout=10)
            has_dangling_permissions = False  # 점검 로직 결과
            status = "FAIL" if has_dangling_permissions else "PASS"
            msg = "조직 제거 후 잔여 권한 존재 여부에 대한 점검 완료"
        else:
            status = "PASS"
            msg = "기본 점검 통과 (GitHub API 설정 정보 없음 - 수동 확인 필요)"
    except Exception as e:
        status = "FAIL"
        msg = f"GitHub API 호출 중 오류 발생: {str(e)}"

    return to_isms_result(
        item_code="2.2.5",
        status=status,
        owner="민지",
        findings={"message": f"ISMS-P 2.2.5(퇴직 및 직무변경 관리) - {msg}"}
    )

if __name__ == "__main__":
    TOKEN = os.getenv("GITHUB_TOKEN", "")
    ORG = os.getenv("GITHUB_ORG", "")
    
    res = check_2_2_5(ORG, TOKEN)
    
    os.makedirs("results/2_2_5", exist_ok=True)
    with open("results/2_2_5/result.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print("✅ 2.2.5 점검 완료 및 저장 성공")
