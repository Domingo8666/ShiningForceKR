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
| SFKR-020 | 무입력 attract intro에서도 0x003FD5·0x03FFB2의 0x5F 전용 한국어 페이지 렌더러 호출이 0회 | fixed-emulator | 전용 호출보다 앞선 공용 텍스트 디코더 0x003411도 같은 12,000프레임 경로에서 실행되지 않음을 S25U로 확인 |
| SFKR-021 | 무입력 attract 경로는 추정 텍스트 디코더 0x003411에 도달하지 않고, 이전 새 게임 자동 조작은 확인이 아닌 1번 취소 버튼을 반복함 | fixed-emulator | Start·2번 3,300프레임을 단일 프레임 완료 장벽으로 S25U 재검증 |
| SFKR-022 | 0x003411은 v5.1 BPS의 source-independent 확장 코드나 패치 호출부에서 검증된 진입점이 아닌데 공용 디코더로 가정됨 | fixed-static | BPS에서 확인한 0x0033FA..0x003405 패치 코드와 0x003432 bank 0x20 리터럴을 근거로 0x33FA·0x3411·0x3431 execute 후보를 추적 |
| SFKR-023 | S25U 런타임 준비 검사는 모두 통과했지만 probe 종료 코드 1의 안전 요약이 `runtime-command`까지만 구분됨 | fixed-static | 로컬 전체 오류는 S25U에 보존하고 실패 단계·분류·마지막 MCP 메서드만 schema v3 진단으로 게시한 뒤 자동실행 재수집 |
| SFKR-024 | S25U proot의 180프레임 실행을 PAL 실시간 속도로 가정한 8.6초 완료 제한이 정상 실행을 중단 | fixed-static | 프레임 수와 저속 실행 하한으로 계산하되 180프레임에 최소 60초를 허용하는 bounded 완료 장벽으로 S25U 재실행 |
| SFKR-025 | 장거리 후보 탐색 전체에 CPU trace를 켜 모든 Z80 명령을 기록해 60초 프레임 제한도 소진 | fixed-static | 첫 경로는 trace 없이 mapper 일치·실행 범위 비중첩 read hit를 수집하고 정확한 접근 명령은 짧은 후속 replay로 분리 |
| SFKR-026 | Gearsystem 3.9.14의 multi-frame 예약이 완료되지 않을 때 `debug_pause`로 pending count를 취소할 수 없어 probe가 복구 불가 | fixed-static | 브레이크포인트 감시 구간을 1프레임 단위로 실행하고 매번 paused/breakpoint 완료를 확인 |
| SFKR-027 | 단일 프레임 장벽으로 완료한 Start·2번 3,300프레임 경로에서 상위 정적 조회표 후보와 패치된 디코더 execute 후보가 모두 무히트 | fixed-emulator | 동기화된 무입력 attract intro에서 0x33FA execute hit와 PC 0x3406의 slot 1·bank 8 read를 확인 |
| SFKR-028 | 무입력·버튼 경로 매트릭스가 안전 상한 1,000을 넘는 단일 12,000프레임 요청으로 즉시 종료 | fixed-static | 무입력 총예산은 유지하고 1,000프레임 12구간으로 나누며 renderer schema v3 실패 영수증을 유지 |
| SFKR-029 | 디코더 진입 뒤 첫 64개 표본이 모두 bank 8 source-region read여서 한국어 Huffman bank 0x20 전환 전에 수집 종료 | fixed-emulator | source-region 표본을 8개로 제한한 후 mapper bank 0x20의 Huffman vector/tree 실제 읽기를 수집 |
| SFKR-030 | 실제 stream·vector·tree read 좌표는 확보했지만 공개 증거에 피연산자 역할이 없어 정확한 압축 엔트리 경계를 확정할 수 없음 | fixed-static | opcode는 S25U 로컬에만 두고 고정 operand-kind와 BPS 제한 왕복으로 겹치지 않는 실제 인트로 스트림 4개를 확정 |
| SFKR-031 | 런타임 확정 인트로 스트림의 첫 시험 문장 화면 증거가 아직 없음 | investigating | 정확한 Galmuri7 픽셀 매핑으로 교정한 31비트 `한다`를 확정 엔트리에 Expected Write로 넣고 동일 attract 경로의 S25U PNG를 로컬 캡처 |
| SFKR-032 | 첫 시험 ROM 캡처가 목표 논리 주소의 mapper bank 7 선행 히트를 bank 8 목표로 오인하고 탐색을 종료 | fixed-emulator | 뱅크·디코더 PC가 모두 일치할 때만 승인하고 오탐은 breakpoint 해제·한 명령 진행·재설정 후 계속 탐색 |
| SFKR-033 | 확정 디코더 stream이 있는데도 자동 비교 실행이 초기 탐색을 반복하고 실패 시 `runtime-command`만 기록 | fixed-static | 기준 ROM SHA-256과 검증된 stream resolution이 일치하면 초기 탐색을 건너뛰며 하위 실패 단계를 안전 영수증으로 남긴 뒤 S25U 재실행 |
| SFKR-034 | Gearsystem PNG의 유효한 IEND 뒤 2바이트 NUL 패딩을 엄격 비교기가 구조 불완전으로 거부 | fixed-static | CRC와 IEND를 검증한 뒤 최대 16바이트의 0 패딩만 허용하고 비영·과도한 후행 데이터는 거부한 상태로 S25U 픽셀 비교 재실행 |
| SFKR-035 | 픽셀 변화가 검출돼도 사람이 복잡한 해시별 evidence 경로에서 기준·시험·진행 후 PNG를 직접 찾아야 함 | fixed-static | 변경 픽셀이 가장 많은 짝과 진행 후 PNG를 해시 검증한 뒤 `reports/HUMAN_REVIEW/`에 쉬운 이름으로 복사하고 안내 파일 생성 |
| SFKR-036 | 0x0204B1 중간 read를 실제 선택 대사의 시작으로 오해 | investigating | DE=2·B=147이면 0x43DE 앵커에서 148개 엔트리를 건너뛰며, 0x44B1은 23번째 엔트리(bit 1550..1750)에 속하고 실제 선택된 148번째 엔트리는 bit 12311의 0x49E0..0x49EE임. 물리 0x0209E0의 bit 7부터 교정한 `한다`를 넣어 S25U에서 직접 표시 확인 |
| SFKR-037 | 시험 문구 `한다`의 `한`을 페이지 27·심벌 0x1F로 잘못 식별 | fixed-static | Galmuri7 BDF와 8×8 픽셀을 대조해 `한`=페이지 6·0x11, `다`=페이지 6·0x04로 교정하고 31비트 Huffman 왕복 및 전체 회귀 통과 |

## 테스트 원칙

- 검증된 깨끗한 일본판 ROM에서 항상 새로 빌드합니다.
- 저장 상태를 불러오기 전 콜드 부팅 테스트를 먼저 합니다.
- 화면 문제 영상은 S25U evidence/에 두며 대용량 영상은 Git에 올리지 않습니다.
- 번역 수정은 원문 엔트리와 포인터가 확정된 뒤 사람이 최종 승인합니다.
