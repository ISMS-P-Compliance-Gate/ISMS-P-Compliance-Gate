# 해당 파일은 check_2_6_4.py의 판정 로직만 미리 검증하는 스크립트
# 실제 AWS 자격증명 없이, boto3가 "이런 응답을 받았다"고 가정하고 테스트한다.
# 회의 후 자격증명이 준비되면 이 파일은 지우거나 남겨둬도 무방하다(자동 실행 대상 아님).
# 


from unittest.mock import patch
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent))
from check_2_6_4 import scan_rds

FAKE_RDS_RESPONSE = {
    "DBInstances": [
        {"DBInstanceIdentifier": "prod-db-1", "PubliclyAccessible": True},      # 위반 케이스
        {"DBInstanceIdentifier": "staging-db-1", "PubliclyAccessible": False},  # 정상 케이스
    ]
}

with patch("boto3.client") as mock_client:
    mock_client.return_value.describe_db_instances.return_value = FAKE_RDS_RESPONSE
    findings = scan_rds()

print(f"findings 개수: {len(findings)}")
for f in findings:
    print(f)
