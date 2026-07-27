"""
2.10.9 악성코드 통제

ClamAV 설정 파일 파싱과 프로세스 상태 확인으로
실시간 감시 활성화 및 정의파일 최신화 여부를 점검한다.

[Mock 모드]  MOCK_MODE=true  → sample_targets/clamd.conf 사용, 프로세스 확인 스킵
[실제 모드]  MOCK_MODE=false → /etc/clamav/clamd.conf + 실제 프로세스 확인
"""
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from base import SAMPLE_DIR, ISMSRule, finding, is_mock

CLAMD_CONF_PATHS  = [
    Path("/etc/clamav/clamd.conf"),
    Path("/etc/clamd.conf"),
    Path("/etc/clamd.d/scan.conf"),
]
CLAMAV_DB_PATHS   = [
    Path("/var/lib/clamav/main.cvd"),
    Path("/var/lib/clamav/daily.cvd"),
    Path("/var/lib/clamav/daily.cld"),
]
CLAMAV_LOG_PATH   = Path("/var/log/clamav/clamav.log")
MAX_DEFINITION_AGE_DAYS = 7


class MalwareControlRule(ISMSRule):
    control_id   = "2.10.9"
    control_name = "악성코드 통제"
    category     = "auto"
    tool         = "clamav-parser"

    def check(self) -> dict:
        findings  = []
        conf_path = SAMPLE_DIR / "clamd.conf" if is_mock() else self._find_conf()

        # 1. 백신 프로세스 실행 여부 (실제 모드만)
        if not is_mock() and not self._is_clamd_running():
            findings.append(finding(
                "ClamAV(clamd) 프로세스가 실행 중이지 않음 — 실시간 탐지 불가",
                severity="HIGH", file="ps aux",
            ))

        # 2. 설정 파일 파싱
        if conf_path and Path(conf_path).exists():
            findings += self._check_conf(conf_path)
        else:
            findings.append(finding(
                "ClamAV 설정 파일을 찾을 수 없음 — 백신 미설치 가능성",
                severity="HIGH", file=str(conf_path or "unknown"),
            ))

        # 3. 정의파일 업데이트 날짜 (실제 모드만)
        if not is_mock():
            findings += self._check_definition_age()

        # 4. 스캔 로그 이력 (실제 모드만)
        if not is_mock():
            findings += self._check_scan_log()

        return {
            "status": "FAIL" if findings else "PASS",
            "findings": findings,
            "scope": f"{'[MOCK] ' if is_mock() else ''}{conf_path}",
        }

    def _is_clamd_running(self) -> bool:
        try:
            r = subprocess.run(["pgrep", "-x", "clamd"],
                               capture_output=True, timeout=3)
            return r.returncode == 0
        except Exception:
            return False

    def _check_conf(self, conf_path) -> list:
        findings = []
        try:
            lines = Path(conf_path).read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return findings

        for i, line in enumerate(lines, 1):
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            if re.match(r"OnAccessPrevention\s+no", line, re.I):
                findings.append(finding(
                    "실시간 악성코드 감시(OnAccessPrevention) 비활성화 — 탐지 체계 부재",
                    severity="HIGH", file=str(conf_path), line=i,
                ))
            if re.match(r"OnAccessExtraScanning\s+no", line, re.I):
                findings.append(finding(
                    "OnAccessExtraScanning 비활성화 — 감시 범위 축소",
                    severity="MEDIUM", file=str(conf_path), line=i,
                ))
        return findings

    def _check_definition_age(self) -> list:
        for db in CLAMAV_DB_PATHS:
            if db.exists():
                mtime   = datetime.fromtimestamp(db.stat().st_mtime, tz=timezone.utc)
                age     = (datetime.now(timezone.utc) - mtime).days
                if age > MAX_DEFINITION_AGE_DAYS:
                    return [finding(
                        f"바이러스 정의파일 {age}일 미업데이트 — 기준({MAX_DEFINITION_AGE_DAYS}일) 초과",
                        severity="MEDIUM", file=str(db),
                    )]
                return []
        return []

    def _check_scan_log(self) -> list:
        if not CLAMAV_LOG_PATH.exists():
            return [finding(
                "ClamAV 스캔 로그 없음 — 정기 스캔 이력 미확인",
                severity="LOW", file=str(CLAMAV_LOG_PATH),
            )]
        content = CLAMAV_LOG_PATH.read_text(encoding="utf-8", errors="ignore")
        if "Infected files:" not in content:
            return [finding(
                "최근 전체 스캔 이력 없음 — 정기 스캔 미수행",
                severity="LOW", file=str(CLAMAV_LOG_PATH),
            )]
        return []

    def _find_conf(self):
        for p in CLAMD_CONF_PATHS:
            if p.exists():
                return p
        return None


if __name__ == "__main__":
    MalwareControlRule().run()
