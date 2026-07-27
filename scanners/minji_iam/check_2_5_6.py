import os
import json
import boto3
from datetime import datetime, timedelta, timezone
from lib.mapping import to_isms_result

def check_2_5_6():
    try:
        cloudtrail = boto3.client('cloudtrail')
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=90)
        response = cloudtrail.lookup_events(
            LookupAttributes=[{'AttributeKey': 'EventSource', 'AttributeValue': 'iam.amazonaws.com'}],
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=10
        )
        events = response.get('Events', [])
        status = "PASS" if len(events) > 0 else "CHECKLIST"
        message = "ISMS-P 2.5.6(접근권한 검토) - 최근 IAM 권한 변경 및 감사 로그 이력이 스캔되었습니다."
    except Exception as e:
        status = "CHECKLIST"
        message = f"ISMS-P 2.5.6(접근권한 검토) - 감사 로그 조회 실패 ({str(e)})."

    result = to_isms_result(
        control_id="2.5.6",
        control_name="접근권한 검토",
        status=status,
        tool="AWS CloudTrail API",
        findings={"message": message}
    )
    return result

if __name__ == "__main__":
    res = check_2_5_6()
    os.makedirs("results/2_5_6", exist_ok=True)
    with open("results/2_5_6/result.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print("✅ 2.5.6 점검 완료")
