# 재작업 이슈 추적표

상태값: open, investigating, blocked, fixed-static, fixed-emulator

정적 분석으로 고쳐도 실제 에뮬레이터 재현 검증 전에는 fixed-emulator로 표시하지 않습니다.

| ID | 증상 | 상태 | 다음 확인 |
|---|---|---|---|
| SFKR-001 | 대사 전환 시 검은 깜빡임 | open | 화면 비활성화 구간과 VBlank 타이밍 추적 |
| SFKR-002 | A 버튼 진행 시 이전 글자나 잘못된 한글이 순간 표시 | open | 타일맵 지우기와 VRAM 갱신 순서 기록 |
| SFKR-003 | 대사 진행 역삼각형 표시 타이밍 이상 | open | 제어 코드와 입력 대기 상태 머신 대조 |
| SFKR-004 | 지누구그 같은 깨진 문자열 | investigating | 조회표, 사전 토큰, Huffman 문맥 검증 |
| SFKR-005 | 부자연스럽거나 문맥에 맞지 않는 번역 | open | 원문 확정 뒤 엔트리별 사람 검수 |
| SFKR-006 | 세이브 상태의 이전 VRAM/폰트가 테스트 오염 | open | 콜드 부팅과 새 게임 기준 재검증 |
| SFKR-007 | 대사창 테두리와 주변 그래픽 손상 위험 | open | 글리프 업로드 범위와 타일 인덱스 경계 검사 |
| SFKR-008 | 실제 스크립트 조회표 미확정 | investigating | 표 히트 뒤 후보 압축 주소의 read breakpoint와 매퍼 뱅크 일치 확인 |
| SFKR-009 | 한국어 문맥·제어 심벌 의미 미확정 | investigating | 확인된 51개 문맥을 글꼴 페이지·화면 동작과 연결 |
| SFKR-010 | 목표 인트로 문장 ROM 디코딩 미완료 | blocked | 정확한 조회표 엔트리 ID 확인 뒤 재개 |
| SFKR-011 | 추적 계획 추가 뒤 모바일 파이프라인 SyntaxError | fixed-static | compileall 및 파이프라인 import 회귀 통과 후 S25U 재실행 |
| SFKR-012 | 0x4000/0x8000의 흔한 JP/CALL이 0x010000 후보를 과대평가 | fixed-static | 제어 흐름 점수 제외와 슬롯 시작 주소 감점 뒤 S25U 후보 재산정 |
| SFKR-013 | S25U Ubuntu 패키지 처리 exit 100 뒤 Gearsystem 바이너리 미설치 | fixed-static | 불필요한 GL 패키지 제거, apt 복구·재시도와 단계별 종료 코드 적용 뒤 S25U 재실행 |
| SFKR-014 | 같은 진단 결과가 반복되면 새 모바일 실행 여부를 GitHub에서 구분할 수 없음 | fixed-static | 경로 없는 UTC 실행 시각을 진단 스키마 v2에 추가해 실행마다 검증된 영수증 게시 |
| SFKR-015 | 테스트 ROM 생성 뒤 화면 증거가 수동 캡처에만 의존 | fixed-static | 확정 엔트리 read와 mapper bank를 다시 확인한 뒤 표시 시점 4장과 A 버튼 진행 뒤 1장을 S25U 로컬에 자동 캡처하고 경로 없는 메타데이터만 게시 |
| SFKR-016 | 슬롯 2의 같은 논리 주소를 다른 매퍼 뱅크에서 읽은 히트가 물리 뱅크 0 조회표 증거로 잘못 승격 | fixed-static | 논리 범위와 슬롯 매퍼 뱅크가 모두 일치하는 히트만 채택하고 불일치 히트 뒤 탐색을 계속한 다음 S25U 재실행 |
| SFKR-017 | 최상위 물리 뱅크 0 조회표 후보가 스크립트 입력 구간에서 실제로 읽히지 않음 | investigating | 직전 무히트 범위를 자동 제외하고 bounded decode 가능한 다음 2개 3바이트 후보군을 같은 S25U 실행에서 순차 추적 |
| SFKR-018 | 정적 상위 3바이트 조회표 후보군 세 곳 모두 입력 구간에서 실제 읽기 0회 | investigating | 추정 조회표 확대를 중단하고 검증된 v5.1 한글 렌더러 호출 좌표 0x003FD5·0x03FFB2의 execute hit와 mapper bank를 역추적 |
| SFKR-019 | 렌더러 추적 자동화가 콜드 부팅 180프레임 뒤 Start와 1번 버튼을 눌러 무입력 도입 장면을 건너뜀 | fixed-emulator | 여섯 execute breakpoint를 한 콜드 부팅에 동시에 설치하고 12,000프레임 무입력 attract intro를 S25U에서 재추적 완료 |
| SFKR-020 | 무입력 attract intro에서도 0x003FD5·0x03FFB2의 0x5F 전용 한국어 페이지 렌더러 호출이 0회 | fixed-static | 전용 호출보다 앞선 공용 텍스트 디코더 0x003411을 추적하고, 히트 직후 slot 1·2 ROM 데이터 읽기의 논리 주소·매퍼 뱅크·물리 좌표를 자동 수집 |

## 테스트 원칙

- 검증된 깨끗한 일본판 ROM에서 항상 새로 빌드합니다.
- 저장 상태를 불러오기 전 콜드 부팅 테스트를 먼저 합니다.
- 화면 문제 영상은 S25U evidence/에 두며 대용량 영상은 Git에 올리지 않습니다.
- 번역 수정은 원문 엔트리와 포인터가 확정된 뒤 사람이 최종 승인합니다.
