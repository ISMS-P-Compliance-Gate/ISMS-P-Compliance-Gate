"""
2.9.3 백업 및 복구관리

crontab을 파싱해 백업 스케줄 존재 여부와 주기를 확인하고,
백업 로그 파일로 최근 백업 성공 이력을 검증한다.

[Mock 모드]  MOCK_MODE=true  → sample_targets/crontab 사용
[실제 모드]  MOCK_MODE=false → /etc/crontab 사용
"""
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from base import SAMPLE_DIR, ISMSRule, finding, is_mock

REAL_CRONTAB     = Path("/etc/crontab")
BACKUP_KEYWORDS  = ["backup", "rsync", "mysqldump", "pg_dump", "tar", "rclone"]
BACKUP_LOG_PATHS = [Path("/var/log/backup.log"), Path("/var/log/backup/backup.log")]
MAX_INTERVAL_DAYS = 7
MAX_AGE_DAYS      = 30


class BackupRecoveryRule(ISMSRule):
    control_id   = "2.9.3"
    control_name = "백업 및 복구관리"
    category     = "auto"
    tool         = "crontab-parser"

    def check(self) -> dict:
        crontab_path = SAMPLE_DIR / "crontab" if is_mock() else REAL_CRONTAB
        findings     = []
        jobs         = self._collect_jobs(crontab_path)
        backup_jobs  = [j for j in jobs if any(k in j["cmd"].lower() for k in BACKUP_KEYWORDS)]

        # 1. 백업 스케줄 확인
        if not backup_jobs:
            findings.append(finding(
                "백업 관련 cron job이 존재하지 않음 — 자동 백업 미설정",
                severity="HIGH", file=str(crontab_path),
            ))
        else:
            for job in backup_jobs:
                interval = self._estimate_interval(job)
                if interval and interval > MAX_INTERVAL_DAYS:
                    findings.append(finding(
                        f"백업 주기 약 {interval}일 — 권고 기준({MAX_INTERVAL_DAYS}일) 초과",
                        severity="MEDIUM",
                        file=job["file"], line=job["line_no"],
                    ))

        # 2. 백업 로그 확인 (mock 시 로그 파일 없음 시뮬레이션)
        if is_mock():
            findings.append(finding(
                "[MOCK] 백업 로그 파일 없음 — 백업 성공 이력 확인 불가",
                severity="HIGH", file=str(BACKUP_LOG_PATHS[0]),
            ))
        else:
            findings += self._check_backup_log()

        # 3. 복구 테스트 이력
        restore_jobs = [j for j in jobs if any(k in j["cmd"].lower() for k in ["restore", "recover"])]
        if not restore_jobs:
            findings.append(finding(
                "복구 테스트 관련 스케줄 없음 — 정기 복구 테스트 이력 미확인",
                severity="LOW", file=str(crontab_path),
            ))

        return {
            "status": "FAIL" if findings else "PASS",
            "findings": findings,
            "scope": f"{'[MOCK] ' if is_mock() else ''}{crontab_path}",
        }

    def _collect_jobs(self, path: Path) -> list:
        jobs = []
        files = [path] if path.is_file() else sorted(path.iterdir()) if path.is_dir() else []
        for fpath in files:
            try:
                for i, line in enumerate(fpath.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    m = re.match(r"^(\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(?:\S+\s+)?(.+)$", line)
                    if m:
                        jobs.append({"schedule": m.group(1), "cmd": m.group(2),
                                     "file": str(fpath), "line_no": i})
            except Exception:
                continue
        return jobs

    def _estimate_interval(self, job: dict) -> int | None:
        parts = job["schedule"].split()
        if len(parts) < 5:
            return None
        _, _, day, month, dow = parts[:5]
        if month != "*": return 30
        if day   != "*": return 7 if day.startswith("*/") else 30
        if dow   != "*": return 7
        return 1

    def _check_backup_log(self) -> list:
        for log_path in BACKUP_LOG_PATHS:
            if log_path.exists():
                mtime   = datetime.fromtimestamp(log_path.stat().st_mtime, tz=timezone.utc)
                age     = (datetime.now(timezone.utc) - mtime).days
                if age > MAX_AGE_DAYS:
                    return [finding(
                        f"백업 로그 마지막 갱신 {age}일 전 — 최근 {MAX_AGE_DAYS}일 내 백업 없음",
                        severity="HIGH", file=str(log_path),
                    )]
                return []
        return [finding(
            "백업 로그 파일 없음 — 백업 성공 이력 확인 불가",
            severity="HIGH", file=str(BACKUP_LOG_PATHS[0]),
        )]


if __name__ == "__main__":
    BackupRecoveryRule().run()
