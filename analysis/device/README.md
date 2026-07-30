# S25U 안전 관측 데이터

이 폴더에는 S25U 로컬 분석에서 만든 ROM 비포함 요약만 저장합니다.

허용 범위:

- 조회표 후보의 파일 좌표, 항목 수와 점수
- 고유 대상 비율, 단조성, 제한 내 종료율 같은 집계 지표
- 가능한 Game Gear slot, bank와 논리 읽기 범위
- 서로 겹치는 시프트 정렬 후보와 통합 감시 범위
- 정적 명령 모양 개수와 매퍼 결합 개수
- 실제 read breakpoint 히트의 PC·physical PC와 네 개 매퍼 레지스터
- 검증된 렌더러 call-site execute breakpoint의 PC·physical PC와 매퍼 상태
- 실행한 슬롯·프레임 수, trace 항목 수와 호출 스택 깊이
- 실행 소비 증거 및 번역 빌드 적격 여부
- S25U 로컬 테스트 화면의 PNG 해시·크기와 사람 시각 확인 대기 상태
- 기준·시험 PNG의 정규화 픽셀 해시, 변경 픽셀 수와 변경 경계
- 사람 시각 검토의 캡처 해시, 불리언 판정과 다음 후보 좌표
- 사용자가 요청한 최신 시험 화면 1장과 빌드·PNG 해시 영수증

금지 범위:

- 원본 또는 생성 ROM 바이트
- 압축 데이터, 디코딩 원문·번역문
- S25U 로컬 파일 경로와 사용자 정보
- 세이브 상태, 실행 메모리 덤프와 인증 정보
- 기준 화면, 전체 프레임 묶음 또는 이전 진행 화면의 누적 보관

`tools/v5_1_safe_observation.py`는 고정 스키마의 허용 필드만
`v5_1_latest_observation.json`에 기록하고, 알 수 없는 필드가 있으면
게시를 거부합니다.

`tools/v5_1_runtime_observation.py`는 Gearsystem 실행 결과에서 고정된
좌표와 집계값만 `v5_1_latest_runtime_observation.json`에 기록합니다.
실제 trace 줄, opcode, 메모리 덤프와 로컬 파일 경로는 이 폴더에
게시할 수 없습니다. 아래의 해시 검증된 최신 진행 미리보기 1장만
화면 게시 예외입니다.

정적 조회표 후보가 실행 중 읽히지 않으면
`tools/run_s25u_renderer_probe.py`가 검증된 v5.1 한글 렌더러 호출
좌표를 추적합니다. `v5_1_latest_renderer_observation.json`에는 호출
파일 좌표, 논리 주소, 실제 매퍼 뱅크, 레지스터와 trace·호출 스택
집계만 기록하고 전체 trace와 로컬 경로는 게시하지 않습니다.

`tools/v5_1_decoder_stream_resolution.py`는 실제 디코더가 읽은
source-region 시작점을 BPS의 원본 비의존 Huffman 데이터로 다시
디코딩·인코딩합니다. 심벌과 ROM 바이트는 게시하지 않고 시작·종료
좌표, 비트 수, 심벌 수와 왕복 판정만
`v5_1_latest_decoder_stream_resolution.json`에 기록합니다.

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
압축 엔트리 read와 매퍼 뱅크를 다시 확인하고 전체 화면 PNG 묶음을
`evidence/local/`에 저장합니다. `v5_1_latest_display_capture.json`에는
기준·테스트 빌드 해시, 경로 없는 read 정보, PNG 해시·크기와 사람 검토
대기 상태만 기록합니다. `tools/v5_1_progress_preview.py`는 사용자의
진행 사진 요청에 따라 시험 화면 중 가장 늦은 사전 진행 프레임 1장만
`v5_1_latest_progress_preview.png`로 교체 게시합니다. 함께 게시되는
JSON 영수증의 빌드·PNG 해시가 정확히 맞아야 하며, 이 사진이 생겨도
자동작업은 계속됩니다. 기준 화면, 나머지 PNG와 로컬 경로는 게시하지
않습니다.

사람이 로컬 캡처를 확인하면
`tools/v5_1_test_display_review.py`가 캡처와 기준·테스트 빌드 해시에
귀속한 결과를 `v5_1_latest_display_review.json`으로 검증합니다.
자유 문장, 화면 픽셀과 로컬 경로는 넣지 않습니다. 시험 문구가 보이지
않은 스트림은 같은 기준 빌드의 다음 자동실행 후보에서 제외하며,
이 실패만으로 디코더·글리프 경로를 해결됐다고 승격하지 않습니다.

`tools/v5_1_test_display_comparison.py`는 같은 런타임 지점에서 얻은
기준·시험 PNG를 정규화 RGBA 픽셀로 비교합니다.
`v5_1_latest_display_comparison.json`에는 PNG·픽셀 해시, 변경 픽셀 수와
변경 경계만 기록합니다. 네 캡처와 진행 후 캡처가 모두 한 픽셀도
달라지지 않은 경우에만 현재 스트림을 자동 탈락시킵니다. 픽셀이 하나라도
달라지거나 비교가 완전하지 않으면 사람 검토를 유지합니다.
