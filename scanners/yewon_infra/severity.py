"""
==================================================================
ISMS-P 2.6.x / 2.10.x 항목(담당: 이예원, 클라우드 인프라·네트워크) 전용
심각도(Severity) 판정 로직
==================================================================

[이 파일과 lib/severity.py의 관계]
프로젝트 전체가 공유하는 심각도 판단 기준(6단계)과, 어느 항목에서든 쓸 수
있는 공용 함수(classify_from_external_tool)는 레포 루트의 lib/severity.py에 있다. 

이 파일은 그중 '클라우드 인프라·네트워크 스캔'에만 해당하는 세부 판정 로직만 담는다. 
즉 이 파일 = lib/severity.py의 6단계 기준을 보안그룹, sshd_config, RDS, GuardDuty/WAF)에 구체적으로 적용한 버전이다.

전체 6단계 기준 설명은 lib/severity.py 파일 맨 위 주석을 참고할 것.
아래 각 함수에는 "이 상황이 왜 그 단계에 해당하는지"를 함수별로 다시 짧게 설명한다.

[담당 항목과 함수 매칭]
- 2.6.1 네트워크 접근      -> classify_open_port
- 2.6.2 정보시스템 접근    -> classify_ssh_setting
- 2.6.4 데이터베이스 접근  -> classify_public_resource
- 2.10.1 보안시스템 운영   -> classify_service_disabled
- 2.10.2 클라우드 보안     -> lib.severity.classify_from_external_tool (Checkov 결과 그대로 사용)
- 2.6.6, 2.6.7            -> checklist로 낮춰서 severity 판정 자체가 필요 없음
- 2.8.3                   -> PASS/FAIL만 판단, HIGH/MEDIUM 세부 분기 없이 INFO/MEDIUM 고정 사용
==================================================================
"""
import sys
from pathlib import Path

# lib 폴더를 파이썬이 찾을 수 있도록 경로 추가
# (parents[0]=yewon_infra, parents[1]=scanners, parents[2]=레포 루트)
sys.path.append(str(Path(__file__).resolve().parents[2]))

# 외부 도구(Checkov 등) severity 변환은 새로 안 만들고 공용 함수를 그대로 가져와 쓴다.
# 여기서 다시 import해두면, check_2_10_2.py에서는
# "from severity import classify_from_external_tool" 한 줄로 똑같이 쓸 수 있다.
from lib.severity import classify_from_external_tool  # noqa: F401 (재노출 목적, 이 파일 안에서 직접 쓰진 않음)

# 뚫리면 즉시 악용 가능한 "고위험 포트" 목록.
# 22=SSH, 3389=RDP(윈도우 원격데스크톱), 3306=MySQL, 5432=PostgreSQL,
# 6379=Redis, 27017=MongoDB — 전부 "포트가 열려있으면 바로 로그인/접속
# 시도가 가능한" 종류의 서비스라서 고위험군으로 분류했다.
HIGH_RISK_PORTS = {22, 3389, 3306, 5432, 6379, 27017}


def classify_open_port(port: int, cidr: str) -> str | None:
    """
    보안그룹/방화벽 인바운드 규칙의 심각도 판정. (2.6.1, 2.6.7에서 사용)

    - cidr이 "0.0.0.0/0"(전 세계 누구나 접근 가능)이 아니면:
      애초에 전체 공개가 아니므로 위반 대상이 아님 -> None 반환
    - "0.0.0.0/0"이면서 고위험 포트(SSH/DB 등)라면:
      lib/severity.py의 ②(즉시 악용 가능)에 해당 -> HIGH
    - "0.0.0.0/0"이지만 어떤 서비스인지 알 수 없는 임의 포트라면:
      공격자가 "이 포트 뒤에 뭐가 있는지" 먼저 알아내야 하므로,
      lib/severity.py의 ④(조건부 기술 위험)에 해당 -> MEDIUM

    Args:
        port: 열려있는 포트 번호 (예: 22)
        cidr: 허용 대역 (예: "0.0.0.0/0")
    Returns:
        "HIGH" | "MEDIUM" | None (None = 위반 아님)
    """
    if cidr != "0.0.0.0/0":
        return None
    return "HIGH" if port in HIGH_RISK_PORTS else "MEDIUM"


def classify_ssh_setting(key: str) -> str:
    """
    sshd_config(SSH 서버 설정 파일)의 개별 설정 위반 심각도. (2.6.2에서 사용)

    - PermitRootLogin(관리자 계정 직접 로그인 허용)이 켜져 있으면:
      로그인 정보만 뚫리면 바로 서버 전체를 장악당함
      -> lib/severity.py의 ②(즉시 악용 가능) -> HIGH
    - PasswordAuthentication(비밀번호 인증)만 허용되어 있으면:
      키 인증보다 약하긴 하지만 무차별 대입 공격 등 추가 시도가 필요함
      -> lib/severity.py의 ④(조건부 기술 위험) -> MEDIUM
    - 그 외 자잘한 설정 위반:
      -> lib/severity.py의 ⑤(모범사례 미준수) -> LOW

    Args:
        key: sshd_config의 설정 항목 이름 (예: "PermitRootLogin")
    Returns:
        "HIGH" | "MEDIUM" | "LOW"
    """
    if key == "PermitRootLogin":
        return "HIGH"
    if key == "PasswordAuthentication":
        return "MEDIUM"
    return "LOW"


def classify_public_resource(is_public: bool) -> str | None:
    """
    RDS 등 데이터베이스 리소스의 퍼블릭(공개) 접근 가능 여부 판정. (2.6.4에서 사용)

    - 퍼블릭 접근이 가능하면: 데이터베이스 안의 민감정보가 인터넷에
      직접 노출된 것과 같음 -> lib/severity.py의 ②(즉시 침해 가능) -> 항상 HIGH
    - 퍼블릭 접근이 불가능하면: 위반 아님 -> None

    Args:
        is_public: AWS RDS API의 PubliclyAccessible 값 (True/False)
    Returns:
        "HIGH" | None
    """
    return "HIGH" if is_public else None


def classify_service_disabled(is_enabled: bool) -> str | None:
    """
    GuardDuty(위협 탐지), WAF(웹 방화벽) 같은 보안 시스템 자체의
    활성화 여부 판정. (2.10.1에서 사용)

    - 비활성화 상태면: 공격을 받아도 탐지할 수단 자체가 없는 상태이므로,
      "위험이 있다/없다"를 판단할 수조차 없는 가장 심각한 상황으로 취급
      -> lib/severity.py의 ②(즉시 악용 가능한 상태와 동급) -> 항상 HIGH
    - 활성화 상태면: 위반 아님 -> None

    Args:
        is_enabled: 서비스가 켜져 있는지 여부 (True/False)
    Returns:
        "HIGH" | None
    """
    return None if is_enabled else "HIGH"
