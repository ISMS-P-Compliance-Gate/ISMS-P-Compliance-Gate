# test.tf 파일 실행 시 예측 사항: 22번 포트는 HIGH_RISK_PORTS에 있으니 HIGH,
# 8080번은 없으니 MEDIUM이 나와야 한다. 이 예측을 기억해두고 다음 단계를 진행할 것.

# ISMS-P 2.6.1 네트워크 접근 — Terraform 보안그룹의 0.0.0.0/0 허용 규칙 탐지

# [실행 방법]
# python (혹은 python3) scanners/yewon_infra/check_2_6_1.py
# cat results/2_6_1/*.json (Windows는 해당 명령어 치거나 또는 그냥 탐색기에서 파일 열면 됨)
# (주의) 만약 findings가 2건(HIGH 1건, MEDIUM 1건) 나오면? -> 예측 안 맞은 것.
# 예측이 맞지 않을 경우, 더미 파일 내용이나 코드 재확인 필요.

import hcl2
import sys
import os
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))
from lib.mapping import to_isms_result
from severity import classify_open_port


def scan_terraform_dir(tf_dir: str) -> list[dict]:
    findings = []
    for tf_file in Path(tf_dir).rglob("*.tf"):
        with open(tf_file) as f:
            parsed = hcl2.load(f)
        for resource in parsed.get("resource", []):
            sg = resource.get("aws_security_group")
            if not sg:
                continue
            for sg_name, sg_body in sg.items():
                for ingress in sg_body.get("ingress", []):
                    for cidr in ingress.get("cidr_blocks", []):
                        from_port = ingress.get("from_port")
                        severity = classify_open_port(from_port, cidr)
                        if severity:
                            findings.append({
                                "file": str(tf_file),
                                "line": None,
                                "message": f"보안그룹 '{sg_name}'이 포트 {from_port}를 {cidr}에 개방",
                                "severity": severity,
                            })
    return findings


if __name__ == "__main__":
    tf_dir = os.environ.get("TF_DIR", "./terraform")
    findings = scan_terraform_dir(tf_dir)
    to_isms_result(
        run_id=os.environ.get("GITHUB_RUN_ID", "local-test"),
        control_id="2.6.1", control_name="네트워크 접근",
        category="auto", status="FAIL" if findings else "PASS",
        tool="python-hcl2", owner="예원", findings=findings,
    )
