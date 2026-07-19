# Tiny Secondhand Shopping Platform

간단한 중고거래 플랫폼입니다. Flask + Flask-SocketIO + SQLite로 구현되었으며,
회원가입/로그인, 상품 등록/조회/관리, 전체 채팅 및 1:1 채팅, 신고 기반 악성 유저/상품 차단, 유저 간 송금, 상품 검색, 관리자 기능을 모두 포함합니다.

## 주요 기능

- 회원가입 / 로그인 / 로그아웃 (비밀번호 Argon2 해시 저장, 로그인 실패 5회 시 5분 잠금)
- 프로필 조회/수정 (소개글, 비밀번호 변경은 현재 비밀번호 재인증 필요)
- 다른 사용자 프로필 조회 (사용자명, 소개글, 등록 상품 목록)
- 상품 등록 / 조회 / 검색 / 수정 / 삭제 (본인 소유 상품만 수정·삭제 가능)
- 전체 실시간 채팅 및 1:1 채팅 (Socket.IO, 로그인 사용자만 사용 가능, 메시지 길이 제한 및 rate limit 적용)
- 신고 기능 (사용자/상품 대상, 동일 대상 중복 신고 방지, 시간당 신고 횟수 제한)
  - 상품이 3회 이상 신고되면 자동 차단(비활성화)
  - 사용자가 5회 이상 신고되면 자동 휴면(로그인 불가) 처리
- 유저 간 송금 (모의 잔액 시스템, 송금 시 비밀번호 재인증, DB 트랜잭션)
- 관리자 대시보드 (사용자 휴면/해제, 상품 차단/해제/삭제, 신고 내역 조회)

## 환경 세팅

```bash
git clone <본인 저장소 URL>
cd secure-coding
conda env create -f enviroments.yaml
conda activate secure_coding
```

conda 없이 pip만 사용하는 경우:

```bash
pip install -r requirements.txt
```

## 실행 방법

```bash
python app.py
```

최초 실행 시 `market.db` SQLite 파일과 테이블이 자동 생성됩니다.
기본적으로 `http://127.0.0.1:5000` 에서 접속할 수 있습니다.

외부 기기에서 테스트하려면 ngrok으로 포워딩할 수 있습니다.

```bash
sudo snap install ngrok
ngrok http 5000
```

## 관리자 계정 생성

관리자 승격은 보안상 웹 화면이 아닌 서버 CLI로만 가능합니다. 먼저 일반 회원가입을 진행한 뒤,
서버를 실행할 수 있는 환경에서 아래 명령으로 해당 계정을 관리자로 승격합니다.

```bash
flask --app app.py create-admin
```

## 환경변수 (운영 배포 시)

| 변수 | 설명 | 기본값 |
|---|---|---|
| `SECRET_KEY` | Flask 세션 서명 키. 미설정 시 프로세스 시작마다 랜덤 생성되어 재시작 시 기존 세션이 모두 무효화됨 | 랜덤 생성 |
| `FORCE_HTTPS` | `1`로 설정 시 세션 쿠키에 `Secure` 플래그 적용 및 HSTS 헤더 추가 (HTTPS 운영 환경 전용) | `0` |
| `FLASK_DEBUG` | `1`로 설정 시 Flask 디버그 모드 활성화 (운영 환경에서는 반드시 `0`) | `0` |

## 디렉터리 구조

```
app.py                  # 라우트 및 Socket.IO 이벤트
db.py                   # DB 연결/스키마 관리
security.py             # 비밀번호 해시, 입력 검증, 인증 데코레이터, rate limiter
templates/              # Jinja2 템플릿 (admin/, errors/ 하위 폴더 포함)
static/js/              # 로컬로 vendoring한 socket.io 클라이언트 라이브러리
secure_coding_checklist.csv        # 최초 체크리스트 (요구사항)
secure_coding_checklist_result.csv # 체크리스트 항목별 조치 결과
```

## 보안 관련 참고

개발 과정에서 발견/적용한 보안 항목은 `secure_coding_checklist_result.csv` 및 별도 보고서에 정리되어 있습니다.
