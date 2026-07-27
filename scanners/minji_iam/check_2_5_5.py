import os
import json
import boto3
from lib.mapping import to_isms_result

def check_2_5_5():
    try:
        # AWS IAM Client 생성
        iam = boto3.client('iam')
        
        # 1. Root 계정 MFA 설정 및 최근 사용 여부 점검 (Credential Report 활용)
        # 2. AdministratorAccess 정책이 연결된 IAM 사용자/역할 스캔
        response = iam.list_entities_for_policy(
            PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
        )
        
        admin_users = response.get('PolicyUsers', [])
        admin_roles = response.get('PolicyRoles', [])
        
        # 관리자 권한을 가진 계정이 존재할 경우 상세 점검 필요
        total_admins = len(admin_users) + len(admin_roles)
        status = "PASS" if total_admins < 5 else "FAIL" # 예시 임계치 기준
        
        message = f"ISMS-P 2.5.5(특수 계정 및 권한 관리) - 관리자 권한(Admin) 보유 주체 {total_admins}개 감지. 특수 계정의 오남용 여부를 담당자가 확인해 주세요."

    except Exception as e:
        # AWS API 호출 권한이 없거나 로컬 환경인 경우 예외 처리
        status = "FAIL"
        message = f"ISMS-P 2.5.5(특수 계정 및 권한 관리) - IAM API 호출 실패 ({str(e)}). 설정 상태를 점검하세요."

    findings = {"message": message}
    
    result = to_isms_result(
        control_id="2.5.5",
        control_name="특수 계정 및 권한 관리",
        status=status,
        method="semi-auto",
        tool="AWS IAM API",
        findings=findings,
        evidence_path="results/2_5_5/result.json"
    )
    return result

if __name__ == "__main__":
    res = check_2_5_5()
    
    os.makedirs("results/2_5_5", exist_ok=True)
    with open("results/2_5_5/result.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print("✅ 2.5.5 점검 완료 및 저장 성공")
