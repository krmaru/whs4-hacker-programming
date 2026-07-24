# whs4-hacker-programming

###실행 환경

Python 3.10 이상

SQLite

별도의 외부 데이터베이스 서버 불필요

##프로젝트 실행

###1. 저장소 복제

git clone https://github.com/<krmaru>/whs-hacker-programming.git

cd tiny-secondhand-secure

###2. 데이터베이스 초기화

python3 app.py init-db

###3. 관리자 계정 생성

python3 app.py create-admin admin 'qwer1234!A'

###4. 서버 실행

python3 app.py run

브라우저에서 다음 주소로 접속합니다.

http://127.0.0.1:8000

서버 종료:

Ctrl+C

##자동 테스트

python3 -m unittest discover -s tests -v

정상 실행 시 다음과 같이 표시됩니다.

Ran 8 tests
OK
