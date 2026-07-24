# Tiny Second-hand Shopping Platform

외부 라이브러리 없이 Python 표준 라이브러리와 SQLite만으로 구현한 교육용 중고거래 플랫폼입니다. 실제 금전 결제가 아니라 **가상 포인트 송금**만 제공합니다.

## 구현 기능

- 회원가입, 로그인, 로그아웃
- 상품 등록, 목록, 상세 조회, 검색, 판매 완료 처리, 삭제
- 사용자 간 1:1 메시지
- 사용자 및 상품 신고
- 가상 포인트 송금과 거래 내역
- 관리자 사용자 정지/해제, 상품 숨김/복구, 신고·메시지·송금 감사 조회
- 보안: PBKDF2 비밀번호 해시, CSRF, 세션 회전, 입력 검증, SQL 파라미터 바인딩, XSS 이스케이프, 권한 검사, 보안 헤더, 요청 크기 제한, 간단한 Rate Limit

## 요구 환경

- Python 3.10 이상
- macOS, Ubuntu, WSL 등
- 별도 패키지 설치 없음

## 실행 방법

```bash
git clone https://github.com/<YOUR_GITHUB_ID>/tiny-secondhand-secure.git
cd tiny-secondhand-secure
python3 app.py init-db
python3 app.py create-admin admin 'AdminStrong1'
python3 app.py run
```

브라우저에서 `http://127.0.0.1:8000`에 접속합니다.

> 공개 저장소에는 실제 서비스 비밀번호를 기록하지 마세요. 위 관리자 비밀번호는 로컬 데모 예시이며, 본인이 다른 강한 비밀번호로 바꾸는 것을 권장합니다.

## 테스트

```bash
python3 -m unittest discover -s tests -v
```

## 배포 시 환경 변수

```bash
export TINYMARKET_DB=/absolute/path/tiny_market.db
export SECURE_COOKIE=1   # HTTPS 환경에서만
export ENABLE_HSTS=1     # HTTPS 환경에서만
python3 app.py run --host 0.0.0.0 --port 8000
```

실제 외부 공개 시에는 리버스 프록시를 통해 HTTPS를 적용하고, 프로세스 단위 Rate Limit을 Redis 등의 공유 저장소 기반으로 교체해야 합니다.

## 프로젝트 구조

```text
.
├── app.py                 # WSGI 웹 애플리케이션 및 모든 기능
├── schema.sql             # SQLite 데이터베이스 스키마
├── tests/test_app.py      # 기능·보안 테스트
├── REPORT.md              # 개발 전 과정 보고서 원문
├── .gitignore
└── README.md
```

## 보안상 의도적인 설계 변경

1. 실제 송금 대신 가상 포인트 송금으로 범위를 제한했습니다. 실제 금융 거래에는 PG 연동, 본인 인증, TLS, 법적·회계적 통제, 부정거래 탐지가 필요하기 때문입니다.
2. 실시간 전체 채팅 대신 1:1 메시지로 구현했습니다. 3시간 내 검증 가능한 최소 기능을 우선했고, 메시지 길이·빈도·권한을 통제했습니다.
3. 신고 누적만으로 자동 정지하지 않고 관리자 검토 후 차단하도록 했습니다. 자동 차단은 다중 계정 악용과 허위 신고에 취약하기 때문입니다.
