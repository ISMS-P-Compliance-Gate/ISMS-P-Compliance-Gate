# ISMS-P-Compliance-Gate (임시)

PR마다 ISMS-P(정보보호 및 개인정보보호 관리체계) 통제항목을 자동으로 점검하고,
결과를 표준 JSON으로 남긴 뒤 LLM이 조치 코멘트를 달아주는 GitHub Actions 기반
컴플라이언스 게이트입니다.

## 왜 만들었나

ISMS-P 인증 준비 과정에서 반복되는 수동 점검(IAM 설정, 네트워크 접근 제어,
시크릿 유출, TLS 설정, 개인정보 노출 등)을 코드 리뷰 단계에서 자동으로
잡아내기 위해 만들었습니다. 통제항목별로 담당자를 나눠 점검 스크립트를
작성하고, 결과를 하나의 공통 스키마로 모아 PR에 사람이 읽기 좋은 형태로
남깁니다.

## 동작 흐름

1. PR이 열리거나 갱신되면 워크플로우가 트리거됩니다.
2. `scanners/{담당자}/check_*.py` 스크립트들이 각자 맡은 통제항목을 점검하고
   `results/{control_id}/{timestamp}.json`에 결과를 저장합니다.
3. `scripts/aggregate_results.py`가 최신 결과를 모아 전체 요약 리포트를 만듭니다.
4. `lib/remediation.py`가 Gemini API로 통제항목별 조치 코멘트를 배치 생성합니다.
5. `scripts/post_pr_comment.py`가 표+상세 코멘트를 마크다운으로 조립해
   PR에 게시(이미 있으면 수정)합니다.

## 통제항목 커버리지

| 통제항목 | 영역 | 담당 폴더 | 담당자 |
|---|---|---|---|
| 2.2.5, 2.5.2~2.5.6 | IAM / 식별 | `scanners/minji_iam` | 민지 |
| 2.5.1, 2.6.3, 2.7.2, 2.8.2, 2.8.5, 2.8.6, 2.9.1 | CI/CD 파이프라인 | `scanners/seoyun_pipeline` | 서윤 |
| 2.7.1, 2.8.4 | TLS / 개인정보 노출(Presidio) | `scanners/hyemin_scanner` | 혜민 |
| 2.6.1, 2.6.2, 2.6.4, 2.6.6, 2.6.7, 2.8.3, 2.10.1, 2.10.2 | 네트워크 / 인프라(Terraform) | `scanners/yewon_infra` | 예원 |
| 2.9.2~2.9.6, 2.10.9 | 운영(로그·백업·모니터링) | `scanners/jeongeun_ops` | 정은 |

## 빠른 시작

```bash
pip install -r requirements.txt
cp .env.example .env   # GEMINI_API_KEY 등 채우기

# 개별 통제항목 점검
python scanners/yewon_infra/check_2_6_1.py

# 전체 결과 집계
python scripts/aggregate_results.py

# PR 코멘트 미리보기 (LLM 없이 빠르게 구조만 확인)
python scripts/post_pr_comment.py --dry-run --no-llm

# 결과 스키마 검증
python lib/validate.py
```

## 결과 데이터 형식

모든 점검 결과는 `schema/isms-p-result.schema.json`을 따르는 JSON으로
`results/{control_id}/{timestamp}.json`에 저장됩니다.

| 필드 | 설명 |
|---|---|
| `control_id` | ISMS-P 통제항목 번호 (예: `2.6.1`) |
| `category` | `auto` \| `semi-auto` \| `checklist` |
| `status` | `PASS` \| `FAIL` \| `NOT_APPLICABLE` \| `MANUAL_REQUIRED` \| `ERROR` |
| `findings` | `{message, severity, file, line}` 목록 |
| `owner` | 담당자 이름 |

## 새 점검 스크립트 추가하기

1. `scanners/{자기 폴더}/check_{control_id 언더스코어}.py` 생성
2. `lib.mapping.to_isms_result(...)`로 결과를 표준 형식으로 저장
3. 심각도 판정은 `lib/severity.py`의 공통 기준을 우선 사용하고,
   항목별 특수 로직이 필요하면 `scanners/{폴더}/severity.py`에 따로 둠
4. `templates/remediation.yaml`에 해당 `control_id`의 고정 조치 가이드 추가
5. 워크플로우(`isms-p-gate.yml`)의 해당 담당자 스텝은 `check_*.py` 네이밍 규칙만 지키면 자동으로 실행됨

## 필요한 환경변수 / 시크릿

| 변수 | 필수 여부 | 용도 |
|---|---|---|
| `GEMINI_API_KEY` | 필수(코멘트 생성 시) | Gemini 조치 코멘트 생성 |
| `GEMINI_MODEL` | 선택 | 기본값 `gemini-2.5-flash` |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | IAM/인프라 스캐너용 | minji_iam, yewon_infra |
| `SONAR_TOKEN` / `SONAR_PROJECT_KEY` | 2.8.2용 | SonarQube 연동 |
| `ISMS_GATE_TOKEN` | 선택 | 조직 멤버/브랜치 보호 규칙 조회용 PAT |

## 현재 상태 / 알려진 제약

- `scripts/aggregate_results.py` 실행 스텝은 워크플로우에서 아직 주석 처리됨
- `templates/remediation.yaml`은 일부 통제항목만 채워진 상태

## 라이선스

## 파일 구조 및 목적
.github/workflows/isms-p-gate.yml   # PR 트리거 파이프라인 (5명이 파트별로 담당)
lib/
  mapping.py       # 점검 결과 → 표준 JSON(results/*.json)으로 변환·저장
  severity.py      # HIGH/MEDIUM/LOW/INFO 판정 공통 기준
  remediation.py   # Gemini API로 통제항목별 조치 코멘트 배치 생성
  validate.py      # results/*.json을 JSON 스키마로 검증
scanners/
  minji_iam/        # 2.2.5, 2.5.2~2.5.6 (IAM/식별)
  seoyun_pipeline/   # 2.5.1, 2.6.3, 2.7.2, 2.8.2, 2.8.5, 2.8.6, 2.9.1 (CI/CD 파이프라인)
  hyemin_scanner/    # 2.7.1(TLS), 2.8.4(Presidio 기반 PII 탐지)
  yewon_infra/       # 2.6.x(네트워크 접근), 2.8.3 (Terraform/보안그룹)
  jeongeun_ops/       # 2.9.x(운영: 로그/모니터링/백업 등)
schema/isms-p-result.schema.json   # 결과 JSON 공통 스키마
scripts/
  aggregate_results.py   # results/ → 전체 집계 리포트
  post_pr_comment.py     # 집계 결과를 마크다운으로 조립해 PR에 upsert
templates/remediation.yaml   # 통제항목별 고정 조치 가이드 문구
terraform/test.tf, config/sshd_config   # 스캐너 테스트용 더미 대상 파일
requirements.txt


TBD
