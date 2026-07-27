"""
2.9.4 로그 및 접속기록 관리

logrotate.conf를 파싱해서 접속기록 보관기간이
법정 기준(6개월 = 180일) 이상인지 확인한다.

[Mock 모드]  MOCK_MODE=true  → sample_targets/logrotate.conf 사용
[실제 모드]  MOCK_MODE=false → /etc/logrotate.conf 사용
"""
import re
from pathlib import Path

from base import SAMPLE_DIR, ISMSRule, finding, is_mock

REAL_CONF        = Path("/etc/logrotate.conf")
MIN_DAYS         = 180   # 개인정보보호법 접속기록 최소 보관기간
AUTH_KEYWORDS    = ["auth", "secure", "access", "nginx", "apache", "sshd", "audit"]
FREQ_DAYS        = {"daily": 1, "weekly": 7, "monthly": 30, "yearly": 365}


class LogRetentionRule(ISMSRule):
    control_id   = "2.9.4"
    control_name = "로그 및 접속기록 관리"
    category     = "auto"
    tool         = "logrotate-parser"

    def check(self) -> dict:
        conf_path = SAMPLE_DIR / "logrotate.conf" if is_mock() else REAL_CONF

        if not conf_path.exists():
            return {
                "status": "ERROR",
                "findings": [finding(
                    f"logrotate 설정 파일을 찾을 수 없습니다: {conf_path}",
                    severity="HIGH", file=str(conf_path),
                )],
            }

        blocks   = self._parse_blocks(conf_path)
        findings = []

        for block in blocks:
            days     = self._retention_days(block)
            is_auth  = any(k in block["header"].lower() for k in AUTH_KEYWORDS)

            if days is None and is_auth:
                findings.append(finding(
                    f"접속기록 로그 보관기간 미설정: {block['header']}",
                    severity="HIGH",
                    file=str(conf_path), line=block["line_no"],
                ))
            elif days is not None and days < MIN_DAYS:
                findings.append(finding(
                    f"로그 보관기간 {days}일 — 법정 기준({MIN_DAYS}일) 미달: {block['header']}",
                    severity="HIGH" if is_auth else "MEDIUM",
                    file=str(conf_path), line=block["line_no"],
                ))

        # auth 관련 블록 자체가 없으면 별도 결함
        if not any(any(k in b["header"].lower() for k in AUTH_KEYWORDS) for b in blocks):
            findings.append(finding(
                "접속기록(auth/access) 관련 로그 보관 설정 자체 없음 — 법정 의무 미충족",
                severity="HIGH", file=str(conf_path),
            ))

        return {
            "status": "FAIL" if findings else "PASS",
            "findings": findings,
            "scope": f"{'[MOCK] ' if is_mock() else ''}{conf_path}",
        }

    # ── 파싱 유틸 ─────────────────────────────
    def _parse_blocks(self, path: Path) -> list:
        blocks, current, depth = [], None, 0
        for i, raw in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "{" in line:
                current = {"header": line.replace("{", "").strip(),
                           "line_no": i, "freq": None, "rotate": None}
                depth += 1
            elif "}" in line and current:
                depth -= 1
                if depth == 0:
                    blocks.append(current)
                    current = None
            elif current:
                if re.match(r"^(daily|weekly|monthly|yearly)$", line):
                    current["freq"] = line
                m = re.match(r"^rotate\s+(\d+)$", line)
                if m:
                    current["rotate"] = int(m.group(1))
        return blocks

    def _retention_days(self, block: dict) -> int | None:
        if block["rotate"] is None:
            return None
        return block["rotate"] * FREQ_DAYS.get(block["freq"], 30)


if __name__ == "__main__":
    LogRetentionRule().run()
