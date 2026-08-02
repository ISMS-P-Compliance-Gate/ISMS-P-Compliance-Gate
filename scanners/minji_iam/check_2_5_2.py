import sys
import os
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))  # 누락: 이게 없어서 ModuleNotFoundError
from lib.mapping import to_isms_result

if __name__ == "__main__":
    to_isms_result(
        run_id=os.environ.get("GITHUB_RUN_ID", "local-test"),  # 누락: 필수 파라미터
        control_id="2.5.2",
        control_name="사용자 계정 관리",
        category="checklist",       # method="manual" → category로 이름 변경
        status="MANUAL_REQUIRED",   # "MANUAL" → enum에 없는 값
        tool="manual",              # "N/A" → 팀 표기 통일
        owner="민지",                # 누락: 필수 파라미터
        checklist_items=[           # findings(dict) → checklist_items(list)
            "사용자 계정 등록/발급 시 정식 승인 절차를 거쳤습니까?",
            "장기 미사용 계정(휴면 계정)에 대한 주기적인 복구/잠금/삭제 조치가 이루어지고 있습니까?",
        ],
        # evidence_path 삭제: to_isms_result()가 자동 생성/저장
    )
    print("✅ 2.5.2 수동 체크리스트 결과 생성 완료")

# 하단 os.makedirs / open / json.dump 블록 전체 삭제 (to_isms_result()와 중복)
