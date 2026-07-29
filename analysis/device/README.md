# S25U 안전 관측 데이터

이 폴더에는 S25U 로컬 분석에서 만든 ROM 비포함 요약만 저장합니다.

허용 범위:

- 조회표 후보의 파일 좌표, 항목 수와 점수
- 고유 대상 비율, 단조성, 제한 내 종료율 같은 집계 지표
- 가능한 Game Gear slot, bank와 논리 읽기 범위
- 서로 겹치는 시프트 정렬 후보와 통합 감시 범위
- 정적 명령 모양 개수와 매퍼 결합 개수
- 실제 read breakpoint 히트의 PC·physical PC와 네 개 매퍼 레지스터
- 실행한 슬롯·프레임 수, trace 항목 수와 호출 스택 깊이
- 실행 소비 증거 및 번역 빌드 적격 여부
- S25U 로컬 테스트 화면의 PNG 해시·크기와 사람 시각 확인 대기 상태

금지 범위:

- 원본 또는 생성 ROM 바이트
- 압축 데이터, 디코딩 원문·번역문
- S25U 로컬 파일 경로와 사용자 정보
- 세이브 상태, 실행 메모리 덤프와 인증 정보

`tools/v5_1_safe_observation.py`는 고정 스키마의 허용 필드만
`v5_1_latest_observation.json`에 기록하고, 알 수 없는 필드가 있으면
게시를 거부합니다.

`tools/v5_1_runtime_observation.py`는 Gearsystem 실행 결과에서 고정된
좌표와 집계값만 `v5_1_latest_runtime_observation.json`에 기록합니다.
실제 trace 줄, opcode, 메모리 덤프, 화면과 파일 경로는 이 폴더에
게시할 수 없습니다.

런타임 단계가 결과 생성 전에 중단되면
`tools/v5_1_runtime_diagnostic.py`가 proot, Ubuntu, 실행 파일, 동적
의존성, MCP 초기화와 필수 도구의 성공 여부만
`v5_1_latest_runtime_diagnostic.json`에 기록합니다. 오류 메시지와
로컬 경로는 진단 파일에도 허용하지 않습니다.

read breakpoint가 발생하면 `tools/v5_1_runtime_hit_resolver.py`가 로컬
trace에서 제한적으로 지원하는 Z80 읽기 주소를 복원합니다. 매퍼 뱅크,
물리 표 바이트, 정렬 형식, 엔트리 번호, bounded decode와 비트 단위
재인코딩 일치 여부만
`v5_1_latest_consumer_resolution.json`에 기록합니다. 명령 바이트,
엔트리 바이트와 디코딩 심벌은 로컬 보고서 밖으로 내보내지 않습니다.

테스트 ROM이 생성된 뒤 `tools/v5_1_test_display_capture.py`는 확정된
압축 엔트리 read와 매퍼 뱅크를 다시 확인하고 화면 PNG를
`evidence/local/`에만 저장합니다. `v5_1_latest_display_capture.json`에는
기준·테스트 빌드 해시, 경로 없는 read 정보, PNG 해시·크기와 사람 검토
대기 상태만 기록합니다. PNG 픽셀과 로컬 경로는 게시하지 않습니다.
