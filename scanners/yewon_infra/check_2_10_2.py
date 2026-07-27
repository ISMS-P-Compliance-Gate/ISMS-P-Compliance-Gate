# ISMS-P 2.10.2 클라우드 보안 — Checkov 결과 파싱

# [실행 방법]
# python (혹은 python3) scanners/yewon_infra/check_2_10_2.py
# cat results/2_10_2/*.json
# 결과: .tf 파일 하나만으로 여러 건의 findings가 나와도 정상. (보안그룹 관련 툴 외에도 다양한 모범사례 체크가 있기 때문)

import json
import subprocess
import sys
import os
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))
from lib.mapping import to_isms_result
from severity import classify_from_external_tool

RAW_OUTPUT_PATH = "raw_output/checkov_result.json"


def run_checkov(tf_dir: str):
    os.makedirs("raw_output", exist_ok=True)
    result = subprocess.run(
        ["checkov", "-d", tf_dir, "--output", "json"],
        capture_output=True, text=True,
    )
    with open(RAW_OUTPUT_PATH, "w") as f:
        f.write(result.stdout)


def parse_checkov(path: str) -> list[dict]:
    with open(path) as f:
        raw = json.load(f)
    findings = []
    for check in raw.get("results", {}).get("failed_checks", []):
        findings.append({
            "file": check.get("file_path"),
            "line": check.get("file_line_range", [None])[0],
            "message": check.get("check_name"),
            "severity": classify_from_external_tool(check.get("severity")),
        })
    return findings


if __name__ == "__main__":
    tf_dir = os.environ.get("TF_DIR", "./terraform")
    run_checkov(tf_dir)
    findings = parse_checkov(RAW_OUTPUT_PATH)
    to_isms_result(
        run_id=os.environ.get("GITHUB_RUN_ID", "local-test"),
        control_id="2.10.2", control_name="클라우드 보안",
        category="auto", status="FAIL" if findings else "PASS",
        tool="checkov", owner="예원", findings=findings,
    )
