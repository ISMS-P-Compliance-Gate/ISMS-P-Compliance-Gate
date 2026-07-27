import csv
import json
import os
import uuid

from datetime import datetime, timezone
from pathlib import Path

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.predefined_recognizers import PhoneRecognizer


# --------------------------------------------------
# 경로 설정
# --------------------------------------------------

# scanners/hyemin_scanner
BASE_DIR = Path(__file__).resolve().parent

# 저장소 최상위 폴더
REPO_ROOT = BASE_DIR.parents[1]

# 점검 대상 CSV
INPUT_FILE = BASE_DIR / "test_data.csv"

# 결과 저장 폴더
RESULTS_DIR = REPO_ROOT / "results" / "2.8.4"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------
# 실행 정보 설정
# --------------------------------------------------

# GitHub Actions에서는 GITHUB_RUN_ID 사용
# 로컬 실행에서는 UUID 자동 생성
run_id = os.getenv("GITHUB_RUN_ID") or uuid.uuid4().hex

commit_sha = os.getenv("GITHUB_SHA")

pr_number_value = os.getenv("PR_NUMBER")
pr_number = (
    int(pr_number_value)
    if pr_number_value and pr_number_value.isdigit()
    else None
)

file_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_FILE = RESULTS_DIR / f"2_8_4_result_{file_timestamp}.json"

# GitHub 저장소 기준 상대 경로
evidence_path = OUTPUT_FILE.relative_to(REPO_ROOT).as_posix()
input_relative_path = INPUT_FILE.relative_to(REPO_ROOT).as_posix()


# --------------------------------------------------
# Presidio 설정
# --------------------------------------------------

analyzer = AnalyzerEngine()

# 한국 전화번호 탐지기 추가
kr_phone_recognizer = PhoneRecognizer(
    supported_regions=["KR"],
    supported_entity="PHONE_NUMBER",
    supported_language="en",
)

analyzer.registry.add_recognizer(kr_phone_recognizer)


# --------------------------------------------------
# CSV 개인정보 점검
# --------------------------------------------------

findings = []
detected_count = 0
execution_error = None

try:
    with INPUT_FILE.open(
        mode="r",
        encoding="cp949",
        newline=""
    ) as file:
        reader = csv.DictReader(file)

        print("CSV 헤더:", reader.fieldnames)

        if reader.fieldnames is None:
            raise ValueError("CSV 파일에 헤더가 없습니다.")

        for row_number, row in enumerate(reader, start=2):
            print(f"\n[CSV {row_number}행]")

            for column_name, value in row.items():
                text = value or ""

                print(f"  {column_name}: {text!r}")

                results = analyzer.analyze(
                    text=text,
                    entities=["PHONE_NUMBER"],
                    language="en",
                )

                # 같은 위치의 결과가 중복 탐지되는 경우 제거
                unique_results = {
                    (
                        result.entity_type,
                        result.start,
                        result.end
                    ): result
                    for result in results
                }.values()

                for result in unique_results:
                    detected_count += 1

                    detected_value = text[result.start:result.end]

                    print(
                        f"  → 탐지됨: {detected_value} "
                        f"/ 유형: {result.entity_type} "
                        f"/ 점수: {result.score:.2f}"
                    )

                    # 실제 전화번호 값은 결과 JSON에 저장하지 않음
                    findings.append({
                        "file": input_relative_path,
                        "line": row_number,
                        "message": (
                            f"'{column_name}' 열에서 "
                            f"평문 전화번호가 발견되었습니다."
                        ),
                        "severity": "HIGH"
                    })

except Exception as error:
    execution_error = str(error)

    findings.append({
        "file": input_relative_path,
        "line": None,
        "message": f"점검 실행 중 오류가 발생했습니다: {execution_error}",
        "severity": "INFO"
    })


# --------------------------------------------------
# 상태 결정
# --------------------------------------------------

if execution_error:
    status = "ERROR"
elif detected_count > 0:
    status = "FAIL"
else:
    status = "PASS"


# --------------------------------------------------
# 공통 스키마 결과 생성
# --------------------------------------------------

result_data = {
    "schema_version": "1.0",
    "run_id": run_id,
    "control_id": "2.8.4",
    "control_name": "시험 데이터 보안",
    "category": "auto",
    "status": status,
    "tool": "Microsoft Presidio Analyzer",
    "owner": "혜민",
    "timestamp": (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    ),
    "pr_number": pr_number,
    "commit_sha": commit_sha,
    "scope": input_relative_path,
    "findings": findings,
    "evidence_path": evidence_path
}


# --------------------------------------------------
# JSON 결과 저장
# --------------------------------------------------

with OUTPUT_FILE.open(
    mode="w",
    encoding="utf-8"
) as result_file:
    json.dump(
        result_data,
        result_file,
        ensure_ascii=False,
        indent=2
    )


# 터미널 출력
print("\n==============================")
print("ISMS-P 2.8.4 점검 결과")
print("==============================")
print(json.dumps(result_data, ensure_ascii=False, indent=2))

print(f"\n탐지 건수: {detected_count}")
print(f"결과 저장 위치: {evidence_path}")
