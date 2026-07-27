# ISMS-P 2.6.2 정보시스템 접근 — sshd_config의 PermitRootLogin, PasswordAuthentication 검사

# [실행 방법]
# python (혹은 python3) scanners/yewon_infra/check_2_6_2.py
# cat results/2_6_2/*.json
# 결과: findings 2건(root 로그인 HIGH, 비밀번호 인증 MEDIUM) 나오면 성공.

import re
import sys
import os
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))
from lib.mapping import to_isms_result
from severity import classify_ssh_setting


def parse_sshd_config(path: str) -> list[dict]:
    findings = []
    rules = {
        "PermitRootLogin": ("no", "root 계정 직접 로그인이 허용되어 있음"),
        "PasswordAuthentication": ("no", "비밀번호 인증이 허용되어 있음 (키 인증만 허용해야 함)"),
    }
    with open(path) as f:
        content = f.read()
    for key, (expected, message) in rules.items():
        match = re.search(rf"^\s*{key}\s+(\S+)", content, re.MULTILINE | re.IGNORECASE)
        actual = match.group(1).lower() if match else "unset"
        if actual != expected:
            findings.append({
                "file": path, "line": None, "message": message,
                "severity": classify_ssh_setting(key),
            })
    return findings


if __name__ == "__main__":
    config_path = os.environ.get("SSHD_CONFIG_PATH", "./config/sshd_config")
    findings = parse_sshd_config(config_path)
    to_isms_result(
        run_id=os.environ.get("GITHUB_RUN_ID", "local-test"),
        control_id="2.6.2", control_name="정보시스템 접근",
        category="auto", status="FAIL" if findings else "PASS",
        tool="sshd-config-parser", owner="예원", findings=findings,
    )
