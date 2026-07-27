"""
2.9.2 성능 및 장애관리

psutil로 CPU/메모리/디스크 사용률을 수집하고
thresholds.yaml의 임계치 기준과 비교한다.

기획서 4-1-C 기준 "자동화 제외 → checklist" 항목.
임계치 초과는 자동 탐지 가능하므로 findings에 포함하고,
절차적 확인 사항은 checklist_items로 함께 반환한다.
"""
from pathlib import Path

from base import SAMPLE_DIR, ISMSRule, finding, is_mock

CHECKLIST_ITEMS = [
    "최근 30일 내 장애 대응 기록이 있습니까?",
    "장애 처리 절차서(감지→분류→대응→복구→사후조치)가 수립되어 있습니까?",
    "RTO/RPO 목표값이 문서화되어 있습니까?",
    "성능 임계치 초과 시 알림이 자동 발송되도록 설정되어 있습니까?",
]
DEFAULT_T = {"cpu": 80.0, "mem": 85.0, "disk": 90.0}


class PerformanceFaultRule(ISMSRule):
    control_id   = "2.9.2"
    control_name = "성능 및 장애관리"
    category     = "checklist"
    tool         = "psutil"

    def check(self) -> dict:
        findings   = []
        thresholds = self._load_thresholds()

        try:
            import psutil
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory().percent

            if cpu >= thresholds["cpu"]:
                findings.append(finding(
                    f"CPU 사용률 {cpu:.1f}% — critical 임계치({thresholds['cpu']}%) 초과",
                    severity="HIGH", file="system/cpu",
                ))
            if mem >= thresholds["mem"]:
                findings.append(finding(
                    f"메모리 사용률 {mem:.1f}% — critical 임계치({thresholds['mem']}%) 초과",
                    severity="HIGH", file="system/memory",
                ))
            for part in psutil.disk_partitions():
                try:
                    pct = psutil.disk_usage(part.mountpoint).percent
                    if pct >= thresholds["disk"]:
                        findings.append(finding(
                            f"디스크 {part.mountpoint} {pct:.1f}% — critical 임계치({thresholds['disk']}%) 초과",
                            severity="HIGH", file=f"system/disk:{part.mountpoint}",
                        ))
                except PermissionError:
                    continue

        except ImportError:
            findings.append(finding(
                "psutil 미설치 — 실시간 메트릭 수집 불가. pip install psutil 필요.",
                severity="LOW",
            ))

        return {
            "status": "FAIL" if findings else "PASS",
            "findings": findings,
            "checklist_items": CHECKLIST_ITEMS,
        }

    def _load_thresholds(self) -> dict:
        path = SAMPLE_DIR / "thresholds.yaml" if is_mock() else Path("thresholds.yaml")
        if not path.exists():
            return DEFAULT_T
        try:
            import yaml
            raw = yaml.safe_load(path.read_text()).get("performance", {})
            return {
                "cpu":  raw.get("cpu_percent_critical",  DEFAULT_T["cpu"]),
                "mem":  raw.get("memory_percent_critical", DEFAULT_T["mem"]),
                "disk": raw.get("disk_percent_critical",  DEFAULT_T["disk"]),
            }
        except Exception:
            return DEFAULT_T


if __name__ == "__main__":
    PerformanceFaultRule().run()
