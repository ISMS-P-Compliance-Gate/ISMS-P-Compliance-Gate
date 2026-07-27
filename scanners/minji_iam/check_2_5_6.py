import os
import json
import boto3
from datetime import datetime, timedelta
from lib.mapping import to_isms_result

def check_2_5_6():
    try:
        # AWS CloudTrail Client 생성
        cloudtrail = boto3.client('cloudtrail')
        
        # 최근 90일 간 IAM 권한 변경 관련 이벤트 스캔
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=90)
        
        response = cloudtrail.lookup_events(
            LookupAttributes=[
                {
                    'AttributeKey': 'EventSource',
                    'AttributeValue': 'iam.amazonaws.com'
                },
            ],
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=10
        )
        
        events = response.get('Events', [])
        status = "PASS" if len(events) > 0 else "CHECKLIST"
        
        message = "ISMS-P 2.5.6(접근권한 검토) - 최근 IAM 권한 변경 및 감사 로그 이력이 스캔되었습니다. 정기 권한 검토 승인 문서와 대조해 주세요."

    except Exception as e:
        status = "CHECKLIST"
        message = f"ISMS-P 2.5.6(접근권한 검토) - 감사 로그 자동 조회 실패 ({str(e)}). 수동 체크리스트 검토가 필요합니다."

    findings = {"message": message}
    
    result = to_isms_result(
        control_id="2.5.6",
        control_name="접근권한 검토",
        status=status,
        method="semi-auto",
        tool="AWS CloudTrail API",
        findings=findings,
        evidence_path="results/2_5_6/result.json"
    )
    return result

if __name__ == "__main__":
    res = check_2_5_6()
    
    os.makedirs("results/2_5_6", exist_ok=True)
    with open("results/2_5_6/result.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print("✅ 2.5.6 점검 완료 및 저장 성공")
