#[민지]코드가 계속 에러 뜨는 대표적인 이유
# lib 폴더는 루트단에 있는데, 기존 민지 코드는 계속 'scanners/minji_iam/' 안에서 찾고 있었음.

import sys
import os
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))
from lib.mapping import to_isms_result

if __name__ == "__main__":
    to_isms_result(
        run_id=os.environ.get("GITHUB_RUN_ID", "local-test"),  # 누락: 필수 파라미터
        control_id="2.2.5",
        control_name="퇴직 및 직무변경 관리",
        category="checklist",       # method="manual" → category로 이름 변경, 값도 스키마에 맞게
        status="MANUAL_REQUIRED",   # "MANUAL" → enum에 없는 값, 정확한 철자로 수정
        tool="manual",              # "N/A" → 팀 checklist 항목들과 표기 통일
        owner="민지",                # 누락: 필수 파라미터 (없으면 assert 에러)
        checklist_items=[           # findings(dict) → checklist_items(list)로 자리 이동
            "퇴직자 및 직무 변경자의 계정이 즉시 권한 해제/삭제 되었습니까?",
            "공용 계정 및 dangling 권한이 존재하지 않습니까?",
        ],
        # evidence_path 파라미터 삭제: to_isms_result()가 자동 생성/저장하므로 불필요
    )
    print("✅ 2.2.5 수동 체크리스트 결과 생성 완료")

# 아래 os.makedirs / open / json.dump 블록 전체 삭제:
# to_isms_result() 내부에서 이미 저장까지 처리하므로 중복 로직이었음
