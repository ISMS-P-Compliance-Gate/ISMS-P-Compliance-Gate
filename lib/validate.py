import json
import glob
import os
from jsonschema import validate, ValidationError

def validate_all_results():
    # 스키마 파일 경로 설정
    schema_path = os.path.join("schemas", "isms-p-result.schema.json")
    
    if not os.path.exists(schema_path):
        print(f"❌ 스키마 파일을 찾을 수 없습니다: {schema_path}")
        return

    # UTF-8 인코딩으로 스키마 읽기 (cp949 에러 방지)
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    # results 폴더 하위의 모든 json 파일 검증
    json_files = glob.glob("results/*/*.json")
    if not json_files:
        print("❌ 검증할 JSON 파일이 results/ 하위 폴더에 없습니다.")
        return

    for file_path in json_files:
        with open(file_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                validate(instance=data, schema=schema)
                print(f"✅ [PASS] 스키마 검증 성공: {file_path}")
            except ValidationError as e:
                print(f"❌ [FAIL] 스키마 검증 실패: {file_path}\n   사유: {e.message}")
            except json.JSONDecodeError:
                print(f"❌ [FAIL] JSON 형식이 올바르지 않습니다: {file_path}")

if __name__ == "__main__":
    validate_all_results()