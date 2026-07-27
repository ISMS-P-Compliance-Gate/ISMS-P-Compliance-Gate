"""
2.9.5 로그 및 접속기록 점검 (이상징후 탐지)

Elasticsearch API로 이상 로그인 탐지 및 알림 규칙 설정 여부를 확인한다.

기획서 4-1-C 기준 "자동화 제외 → checklist" 항목.
ELK 연동이 가능한 경우 이상징후 자동 탐지도 수행한다.

[Mock 모드]  MOCK_MODE=true  → 이상징후 시뮬레이션 데이터 반환
[실제 모드]  MOCK_MODE=false → ELK_HOST 환경변수로 실제 쿼리
"""
import os

from base import ISMSRule, finding, is_mock

FAILED_LOGIN_THRESHOLD = 100
CHECKLIST_ITEMS = [
    "최근 로그 점검일이 90일을 초과하지 않았습니까?",
    "이상징후 발생 시 알림이 자동 발송됩니까?",
    "정기 로그 검토 회의록 또는 기록이 있습니까?",
]


class LogInspectionRule(ISMSRule):
    control_id   = "2.9.5"
    control_name = "로그 및 접속기록 점검"
    category     = "checklist"
    tool         = "elasticsearch"

    def check(self) -> dict:
        if is_mock():
            return self._mock_result()

        elk_host = os.getenv("ELK_HOST")
        if not elk_host:
            # ELK 없으면 체크리스트 안내로 fallback
            return {
                "status": "MANUAL_REQUIRED",
                "findings": [],
                "checklist_items": CHECKLIST_ITEMS,
                "scope": "ELK_HOST 환경변수 미설정 — 수동 점검 필요",
            }

        return self._elk_result(elk_host)

    def _mock_result(self) -> dict:
        return {
            "status": "FAIL",
            "findings": [
                finding(
                    "[MOCK] 'admin' 계정 로그인 실패 247건/30일 — 이상징후 탐지",
                    severity="HIGH", file="ELK → logstash-auth-* [MOCK]",
                ),
                finding(
                    "[MOCK] ELK 이상징후 알림 규칙(Watcher) 미설정 — 자동 탐지 체계 부재",
                    severity="HIGH", file="ELK Watcher [MOCK]",
                ),
            ],
            "checklist_items": CHECKLIST_ITEMS,
            "scope": "MOCK 시뮬레이션",
        }

    def _elk_result(self, host: str) -> dict:
        try:
            from elasticsearch import Elasticsearch
            es       = Elasticsearch(
                host,
                basic_auth=(os.getenv("ELK_USER", ""), os.getenv("ELK_PASS", "")),
                verify_certs=False,
            )
            findings = []

            # 이상 로그인 탐지
            resp = es.search(
                index="logstash-*",
                body={
                    "query": {"bool": {"must": [
                        {"match": {"event.type": "authentication_failure"}},
                        {"range": {"@timestamp": {"gte": "now-30d"}}},
                    ]}},
                    "aggs": {"by_user": {"terms": {"field": "user.name.keyword", "size": 10}}},
                    "size": 0,
                },
            )
            for bucket in resp["aggregations"]["by_user"]["buckets"]:
                if bucket["doc_count"] >= FAILED_LOGIN_THRESHOLD:
                    findings.append(finding(
                        f"'{bucket['key']}' 계정 로그인 실패 {bucket['doc_count']}건/30일 — 이상징후 탐지",
                        severity="HIGH", file=f"ELK → logstash-auth-* (user={bucket['key']})",
                    ))

            # Watcher 알림 규칙 확인
            try:
                stats       = es.watcher.stats()
                watch_count = stats.get("stats", [{}])[0].get("watch_count", 0)
                if watch_count < 1:
                    findings.append(finding(
                        f"ELK Watcher 알림 규칙 {watch_count}개 — 이상징후 자동 탐지 미구성",
                        severity="HIGH", file="ELK Watcher",
                    ))
            except Exception:
                pass

            return {
                "status": "FAIL" if findings else "PASS",
                "findings": findings,
                "checklist_items": CHECKLIST_ITEMS,
                "scope": host,
            }

        except ImportError:
            return {
                "status": "ERROR",
                "findings": [finding(
                    "elasticsearch 패키지 미설치 — pip install elasticsearch 필요",
                    severity="LOW",
                )],
                "checklist_items": CHECKLIST_ITEMS,
            }
        except Exception as e:
            return {
                "status": "ERROR",
                "findings": [finding(f"ELK 연결 실패: {e}", severity="LOW")],
                "checklist_items": CHECKLIST_ITEMS,
            }


if __name__ == "__main__":
    LogInspectionRule().run()
