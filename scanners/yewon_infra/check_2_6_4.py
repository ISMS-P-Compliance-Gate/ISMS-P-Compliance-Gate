# ISMS-P 2.6.4 데이터베이스 접근 — AWS RDS의 PubliclyAccessible 여부 확인

# 
import boto3
import sys
import os
from pathlib import Path
from dotenv import load_dotenv # .env 파일의 값을 환경변수로 불러옴. 단, .env 파일은 깃에 커밋 금지.

sys.path.append(str(Path(__file__).resolve().parents[2]))
load_dotenv(Path(__file__).resolve().parents[2] / ".env")  # 레포 루트의 .env를 읽어옴
from lib.mapping import to_isms_result # 결과 공통 JSON 형식으로 저장
from severity import classify_public_resource


def scan_rds() -> list[dict]: # AWS RDS 인스턴스를 조회 후 공개 상태인 DB의 Finding 목록을 반환
    findings = []
    client = boto3.client("rds")
    instances = client.describe_db_instances()["DBInstances"]
    for db in instances:
        severity = classify_public_resource(db.get("PubliclyAccessible", False))
        if severity:
            findings.append({
                "file": None, "line": None,
                "message": f"RDS 인스턴스 '{db['DBInstanceIdentifier']}'가 퍼블릭 접근 가능 상태",
                "severity": severity,
            })
    return findings


if __name__ == "__main__":
    findings = scan_rds()
    to_isms_result(
        run_id=os.environ.get("GITHUB_RUN_ID", "local-test"),
        control_id="2.6.4", control_name="데이터베이스 접근",
        category="auto", status="FAIL" if findings else "PASS",
        tool="boto3-rds", owner="예원", findings=findings,
    )
