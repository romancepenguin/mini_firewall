# mini_firewall

캡쳐링한 텍스트파일형태인 패킷을 읽어 분석하는 미니 방화벽입니다.

Raw 소켓을 이용한 방화벽 프로그램

## 기능
- 침입 추적 기능(Trace Route)
- 역 추적 포트 스캔
- DDos 공격 방지(TCP, IP 헤더 표준 위배되는 패킷 판단)
- 공격 패킷 로그 파일 기록 (ErrorLog_Cnt에 IP, 카운트를 기록, ErrorLog에 상세 로그를 기록)

## 패킷 검사 내용(TCP 헤더)
- SYN, FIN이 함께 설정 된 패킷은 오류
- SYN, RST 함께 설정된 패킷은 오류
- FIN, RST 함께 설정된 패킷은 오류
- ACK는 설정 안되어 있고 FIN 설정 되어 있으면 오류
- ACK는 설정 안되어 있고 PSH 설정 되어 있으면 오류
- ACK는 설정 안되어 있고 PSH 설정 되어 있으면 오류
- 모든 플래그 비트값 설정 되어 있지 않으면 오류
- FIN만 설정 되어있으면 오류
- TCP 헤더 길이값이 5보다 작으면 오류

## 패킷 검사 내용(IP 헤더)
- IP 버전은 4나 6만 존재. 이외의 값은 오류
- TTL 값이 0이되면 시간 초과
- TTL 값이 0이거나 음수면 시간초과
- IP 헤더의 길이 값은 5이상
- TCP 프로토콜 인지 체크
- IP 타입의 서비스는 0~6까지만 지원
- 패킷의 전채 길이가 TOTAL_LENGTH랑 일치하지 않으면 오류
- IP CHECKSUM 일치 검사

## 구동 환경
- 우분투
- gcc

## 구동 이미지(sample)
![image](https://user-images.githubusercontent.com/28975774/111062130-71b78b80-84ea-11eb-83c9-64f17324f8fd.png)

