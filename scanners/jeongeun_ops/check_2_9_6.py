"""
2.9.6 시간 동기화

timedatectl / chronyc 로 NTP 동기화 상태와 시간 오프셋을 확인한다.

[Mock 모드]  MOCK_MODE=true  → NTP 비활성화 결함 시뮬레이션
[실제 모드]  MOCK_MODE=false → timedatectl subprocess 실행
"""
import re
import subprocess

from base import ISMSRule, finding, is_mock


class NTPSyncRule(ISMSRule):
    control_id   = "2.9.6"
    control_name = "시간 동기화"
    category     = "auto"
    tool         = "timedatectl/chronyc"

    def check(self) -> dict:
        if is_mock():
            return {
                "status": "FAIL",
                "findings": [finding(
                    "[MOCK] NTP 서비스가 비활성화되어 있음 — 로그 무결성 훼손 가능",
                    severity="HIGH", file="timedatectl [MOCK]",
                )],
                "scope": "MOCK 시뮬레이션",
            }

        findings = []
        td = self._run("timedatectl")
        if td is None:
            return {
                "status": "ERROR",
                "findings": [finding(
                    "timedatectl 명령 실행 실패 — Linux 환경 필요",
                    severity="HIGH",
                )],
            }

        if self._parse_bool(td, r"NTP service:\s*(\S+)") is False:
            findings.append(finding(
                "NTP 서비스가 비활성화되어 있음 — 로그 무결성 훼손 가능",
                severity="HIGH", file="timedatectl",
            ))

        if self._parse_bool(td, r"NTP synchronized:\s*(\S+)") is False:
            findings.append(finding(
                "NTP 동기화 실패 — 시스템 시각이 표준시각과 불일치",
                severity="HIGH", file="timedatectl",
            ))

        chrony = self._run("chronyc tracking")
        if chrony:
            offset = self._parse_offset(chrony)
            if offset is not None and abs(offset) > 1.0:
                findings.append(finding(
                    f"시간 오프셋 {offset:+.3f}s — 허용 기준(±1s) 초과",
                    severity="MEDIUM", file="chronyc tracking",
                ))

        return {
            "status": "FAIL" if findings else "PASS",
            "findings": findings,
            "scope": "timedatectl" + (", chronyc tracking" if chrony else ""),
        }

    def _run(self, cmd: str) -> str | None:
        try:
            r = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=5)
            return r.stdout if r.returncode == 0 else None
        except Exception:
            return None

    def _parse_bool(self, text: str, pattern: str) -> bool | None:
        m = re.search(pattern, text, re.IGNORECASE)
        if not m:
            return None
        return m.group(1).lower() in ("yes", "active", "true")

    def _parse_offset(self, text: str) -> float | None:
        m = re.search(r"System time\s*:\s*([\+\-]?\d+\.\d+)\s*seconds", text)
        return float(m.group(1)) if m else None


if __name__ == "__main__":
    NTPSyncRule().run()
