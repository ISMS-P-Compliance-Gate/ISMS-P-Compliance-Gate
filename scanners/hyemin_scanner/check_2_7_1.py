#!/usr/bin/env python3
"""
ISMS-P 2.7.1 (암호정책 적용) - 전송구간 자동 점검 스크립트
------------------------------------------------------------
testssl.sh 를 이용해 지정한 대상(도메인:포트)의
  1) TLS 버전
  2) Cipher Suite
  3) 인증서(만료일, 키 길이, 자체서명 여부)
을 스캔하고, ISMS-P 기준에 맞춰 Pass/Fail을 자동 판정한다.
결과는 프로젝트 공통 스키마(schema_version 1.0)의 JSON으로 출력한다.

사전 준비:
  git clone --depth 1 https://github.com/drwetter/testssl.sh.git
  (Docker 불필요. bash + openssl + dig/nslookup + hexdump 필요 -> WSL/리눅스 환경 권장)
  Ubuntu/Debian 계열에 필요한 패키지: apt-get install -y dnsutils bsdmainutils

사용법 (로컬, testssl.sh를 스크립트와 같은 폴더에 clone 해둔 경우):
  python3 check_2_7_1.py --target expired.badssl.com:443 --owner 혜민
  (testssl.sh 경로를 안 주면 ./testssl.sh/testssl.sh 등 흔한 위치를 자동으로 찾음)

  결과는 results/2_7_1/<타임스탬프>.json 에,
  testssl.sh 원본 증적은 results/2_7_1/evidence/ 에 자동 저장됨.

사용법 (GitHub Actions 등 CI):
  python3 check_2_7_1.py --target expired.badssl.com:443 \
      --testssl-path /tmp/testssl.sh/testssl.sh
  (run_id / pr_number / commit_sha는 GITHUB_RUN_ID, GITHUB_SHA, GITHUB_EVENT_NUMBER
   환경변수에서 자동으로 채워짐 -> 인자로 안 넘겨도 됨)
"""

import argparse
import json
import os
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path


# ------------------------------------------------------------------
# 공통 스키마 상수
# ------------------------------------------------------------------
SCHEMA_VERSION = "1.0"
CONTROL_ID = "2.7.1"
CONTROL_NAME = "암호정책 적용 (전송구간)"
TOOL_NAME = "testssl.sh"

# ------------------------------------------------------------------
# ISMS-P 2.7.1 판정 기준값
# ------------------------------------------------------------------
ALLOWED_PROTOCOLS = {"TLS1_2", "TLS1_3"}
DEPRECATED_PROTOCOLS = {
    "SSLv2": "SSLv2",
    "SSLv3": "SSLv3",
    "TLS1": "TLS 1.0",
    "TLS1_1": "TLS 1.1",
}
WEAK_CIPHER_KEYWORDS = [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "anon", "ADH", "AECDH", "PSK",
]
MIN_KEY_SIZE = 2048
CERT_EXPIRY_WARN_DAYS = 30


# ------------------------------------------------------------------
# testssl.sh 경로 탐색
#   --testssl-path로 명시하면 그걸 최우선으로 쓰고,
#   안 주면 로컬/CI 양쪽에서 자주 쓰는 위치들을 순서대로 확인한다.
# ------------------------------------------------------------------
DEFAULT_TESTSSL_CANDIDATES = [
    "./testssl.sh/testssl.sh",
    "~/testssl.sh/testssl.sh",
    "/tmp/testssl.sh/testssl.sh",
    "/opt/testssl.sh/testssl.sh",
]


def resolve_testssl_path(explicit_path):
    candidates = [explicit_path] if explicit_path else []
    candidates += DEFAULT_TESTSSL_CANDIDATES

    for candidate in candidates:
        if not candidate:
            continue
        expanded = os.path.expanduser(candidate)
        if os.path.isfile(expanded):
            return expanded

    tried = ", ".join(os.path.expanduser(c) for c in candidates if c)
    sys.exit(
        "[!] testssl.sh 경로를 찾을 수 없습니다.\n"
        f"    시도한 경로: {tried}\n"
        "    git clone --depth 1 https://github.com/drwetter/testssl.sh.git 로 먼저 받아두거나\n"
        "    --testssl-path 로 정확한 경로를 지정해주세요."
    )


# ------------------------------------------------------------------
# testssl.sh 실행
# ------------------------------------------------------------------
def run_testssl(testssl_path: str, target: str, raw_json_out: Path) -> None:
    cmd = [
        "bash", testssl_path,
        "--jsonfile", str(raw_json_out),
        "--protocols",
        "--cipher-per-proto",
        "-S",
        "--warnings", "off",
        "--color", "0",
        target,
    ]
    print(f"[*] testssl.sh 실행 중: {target}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode not in (0, 1, 2):
        print("[!] testssl.sh 실행 중 경고 발생 (계속 진행):")
        print(result.stderr[-1000:])


def load_raw_findings(raw_json_out: Path) -> list:
    with raw_json_out.open("r", encoding="utf-8") as f:
        data = json.load(f)

    flat = []
    if isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict) and "id" in entry:
                flat.append(entry)
            elif isinstance(entry, list):
                flat.extend(entry)
    return flat


# ------------------------------------------------------------------
# 개별 판정 함수 (각각 하나의 finding으로 변환됨)
# ------------------------------------------------------------------
def check_protocols(raw: list) -> dict:
    ok, bad = [], []
    for item in raw:
        proto_id = item.get("id", "")
        finding = item.get("finding", "")
        if proto_id in DEPRECATED_PROTOCOLS:
            if "offered" in finding.lower() and "not offered" not in finding.lower():
                bad.append({"protocol": DEPRECATED_PROTOCOLS[proto_id], "raw": finding})
        elif proto_id in ALLOWED_PROTOCOLS:
            if "offered" in finding.lower() and "not offered" not in finding.lower():
                ok.append({"protocol": proto_id, "raw": finding})

    passed = len(bad) == 0
    return {
        "check_id": "tls_version",
        "title": "TLS 버전",
        "status": "PASS" if passed else "FAIL",
        "description": (
            "TLS 1.2/1.3만 지원함"
            if passed
            else f"취약한 프로토콜 지원 발견: {[b['protocol'] for b in bad]}"
        ),
        "detail": {"안전한_버전": ok, "취약한_버전": bad},
    }


def _is_weak_cipher_name(name: str) -> bool:
    """cipher '이름' 하나만 놓고 취약 키워드 매칭 (인증서 PEM 텍스트 등 오탐 방지)."""
    upper = name.upper()
    return any(kw.upper() in upper for kw in WEAK_CIPHER_KEYWORDS)


def check_ciphers(raw: list) -> dict:
    # cipher_name -> set(어떤 프로토콜/항목에서 발견됐는지)
    weak_by_cipher = {}

    for item in raw:
        cid = item.get("id", "")
        finding = item.get("finding", "")
        if not finding:
            continue

        # 인증서 PEM 원문 등은 cipher 판정 대상이 아님 (오탐 방지)
        if cid == "cert" or cid.startswith("cert_"):
            continue

        lowered = finding.lower()
        if "not vulnerable" in lowered or "no cipher" in lowered or "offers no" in lowered:
            continue

        if cid.startswith("supportedciphers_"):
            # 예: "ECDHE-RSA-AES256-GCM-SHA384 ... DES-CBC3-SHA" (공백 구분 cipher 목록)
            protocol_label = cid.replace("supportedciphers_", "")
            for cipher_name in finding.split():
                if _is_weak_cipher_name(cipher_name):
                    weak_by_cipher.setdefault(cipher_name, set()).add(protocol_label)

        elif cid.startswith("cipher-"):
            # 예: "TLSv1.2   xc012   ECDHE-RSA-DES-CBC3-SHA   ECDH 256   3DES ..."
            tokens = finding.split()
            if len(tokens) >= 3:
                protocol_label, cipher_name = tokens[0], tokens[2]
            else:
                protocol_label, cipher_name = cid, finding
            if _is_weak_cipher_name(cipher_name):
                weak_by_cipher.setdefault(cipher_name, set()).add(protocol_label)

        else:
            # 그 외 형식은 finding 문자열 자체에서 키워드 매칭 (보수적으로만 사용)
            if any(kw.lower() in lowered for kw in WEAK_CIPHER_KEYWORDS):
                weak_by_cipher.setdefault(finding[:80], set()).add(cid)

    weak = [
        {"cipher": cipher, "protocols": sorted(protocols)}
        for cipher, protocols in weak_by_cipher.items()
    ]
    passed = len(weak) == 0
    return {
        "check_id": "cipher_suite",
        "title": "Cipher Suite",
        "status": "PASS" if passed else "FAIL",
        "description": (
            "취약 Cipher(RC4/DES/NULL 등) 미탐지"
            if passed
            else f"취약 Cipher {len(weak)}종 발견: {', '.join(w['cipher'] for w in weak)}"
        ),
        "detail": {"취약_cipher": weak},
    }


def check_certificate(raw: list) -> dict:
    issues = []
    cert_info = {}

    for item in raw:
        cid = item.get("id", "")
        finding = item.get("finding", "")

        if cid in ("cert_expirationStatus", "cert_expiration"):
            cert_info["expiration_raw"] = finding
            if "expired" in finding.lower():
                issues.append(f"인증서 만료됨: {finding}")
            else:
                m = re.search(r"(\d+)\s*days?", finding)
                if m and int(m.group(1)) <= CERT_EXPIRY_WARN_DAYS:
                    issues.append(f"인증서 만료 임박({m.group(1)}일 이내): {finding}")

        elif cid in ("cert_trust", "cert_chain_of_trust"):
            cert_info["trust"] = finding
            if "self signed" in finding.lower() or "self-signed" in finding.lower():
                issues.append(f"자체서명(Self-signed) 인증서: {finding}")
            if "not trusted" in finding.lower():
                issues.append(f"신뢰되지 않는 인증서 체인: {finding}")

        elif cid == "cert_keySize":
            cert_info["key_size"] = finding
            m = re.search(r"(\d+)\s*bits?", finding)
            if m and int(m.group(1)) < MIN_KEY_SIZE:
                issues.append(f"인증서 키 길이 미달({m.group(1)}bit < {MIN_KEY_SIZE}bit)")

    passed = len(issues) == 0
    return {
        "check_id": "certificate",
        "title": "인증서",
        "status": "PASS" if passed else "FAIL",
        "description": "인증서 유효/신뢰/키길이 이상 없음" if passed else "; ".join(issues),
        "detail": cert_info,
    }


# ------------------------------------------------------------------
# CI 환경변수 기본값 (GitHub Actions 기준. 없으면 로컬 인자/기본값 사용)
# ------------------------------------------------------------------
def default_run_id() -> str:
    return os.environ.get("GITHUB_RUN_ID") or str(uuid.uuid4())


def default_pr_number():
    val = os.environ.get("GITHUB_EVENT_NUMBER") or os.environ.get("PR_NUMBER")
    return int(val) if val and val.isdigit() else None


def default_commit_sha():
    return os.environ.get("GITHUB_SHA") or None


def control_folder_name() -> str:
    """'2.7.1' -> '2_7_1' (팀 results/ 폴더 네이밍 컨벤션)"""
    return CONTROL_ID.replace(".", "_")


def timestamp_for_filename(dt: datetime) -> str:
    """'2026-07-16T09-00-00Z' 형태 (results/2_7_2/2026-07-16T09-00-00Z.json 과 동일 포맷)"""
    return dt.strftime("%Y-%m-%dT%H-%M-%SZ")


# ------------------------------------------------------------------
# main
# ------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="ISMS-P 2.7.1 전송구간 암호정책 자동 점검")
    parser.add_argument("--target", required=True, help="점검 대상 (예: expired.badssl.com:443)")
    parser.add_argument(
        "--testssl-path",
        default=None,
        help="testssl.sh 스크립트 경로 (미지정시 ./testssl.sh/testssl.sh 등 흔한 위치를 자동 탐색)",
    )
    parser.add_argument("--owner", default=os.environ.get("CONTROL_OWNER", "미지정"), help="점검 담당자")
    parser.add_argument("--run-id", default=None, help="실행 ID (미지정시 GITHUB_RUN_ID 또는 uuid)")
    parser.add_argument("--pr-number", type=int, default=None, help="PR 번호 (미지정시 GITHUB_EVENT_NUMBER)")
    parser.add_argument("--commit-sha", default=None, help="커밋 SHA (미지정시 GITHUB_SHA)")
    parser.add_argument(
        "--results-root",
        default="results",
        help="결과 저장 루트 폴더 (기본: results/ -> results/2_7_1/<timestamp>.json 형태로 저장)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="결과 JSON 저장 경로 직접 지정 (지정 시 --results-root 규칙 대신 이 경로를 그대로 사용)",
    )
    parser.add_argument(
        "--evidence-dir",
        default=None,
        help="testssl.sh 원본(raw) 결과 저장 폴더 (미지정시 results/2_7_1/evidence)",
    )
    args = parser.parse_args()

    now = datetime.now(timezone.utc)
    folder = control_folder_name()  # "2_7_1"

    # 팀 컨벤션: results/2_7_1/2026-07-16T09-00-00Z.json
    output_file = (
        Path(args.output)
        if args.output
        else Path(args.results_root) / folder / f"{timestamp_for_filename(now)}.json"
    )
    evidence_dir = (
        Path(args.evidence_dir)
        if args.evidence_dir
        else Path(args.results_root) / folder / "evidence"
    )
    output_file.parent.mkdir(parents=True, exist_ok=True)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    run_id = args.run_id or default_run_id()
    pr_number = args.pr_number if args.pr_number is not None else default_pr_number()
    commit_sha = args.commit_sha or default_commit_sha()

    testssl_path = resolve_testssl_path(args.testssl_path)

    safe_target_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", args.target)
    evidence_path = evidence_dir / f"testssl_{safe_target_name}_{run_id}.json"

    # 1) testssl.sh 실행 -> 원본(raw) 증적 JSON 저장
    run_testssl(testssl_path, args.target, evidence_path)
    raw_findings = load_raw_findings(evidence_path)

    # 2) 세 가지 세부 항목 판정 -> findings 배열로 변환
    findings = [
        check_protocols(raw_findings),
        check_ciphers(raw_findings),
        check_certificate(raw_findings),
    ]
    overall_status = "PASS" if all(f["status"] == "PASS" for f in findings) else "FAIL"

    # --------------------------------------------------
    # 공통 스키마 결과 생성 (다른 항목들과 동일한 구조)
    # --------------------------------------------------
    result_data = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "control_id": CONTROL_ID,
        "control_name": CONTROL_NAME,
        "category": "auto",
        "status": overall_status,
        "tool": TOOL_NAME,
        "owner": args.owner,
        "timestamp": now.isoformat().replace("+00:00", "Z"),
        "pr_number": pr_number,
        "commit_sha": commit_sha,
        "scope": args.target,
        "findings": findings,
        "evidence_path": str(evidence_path),
    }

    # --------------------------------------------------
    # JSON 결과 저장
    # --------------------------------------------------
    with output_file.open(mode="w", encoding="utf-8") as result_file:
        json.dump(
            result_data,
            result_file,
            ensure_ascii=False,
            indent=2,
        )

    print(json.dumps(result_data, ensure_ascii=False, indent=2))
    print(f"\n[*] 결과 저장됨: {output_file}")
    print(f"[*] 원본 증적 저장됨: {evidence_path}")

    # CI에서 실패 시 파이프라인 fail 처리하고 싶으면 exit code 활용
    sys.exit(0 if overall_status == "PASS" else 1)


if __name__ == "__main__":
    main()
