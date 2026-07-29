# Shining Force Gaiden: Final Conflict 한국어 패치 인수인계

## 대상과 저장 위치

- 플랫폼: Sega Game Gear
- 게임: Shining Force Gaiden: Final Conflict (Japan)
- 메가 CD판이 아닙니다.
- 기준 저장소: https://github.com/Domingo8666/ShiningForceKR
- ROM 작업 위치: S25U 내부 저장공간/ShiningForceKR
- PC는 프로젝트 자료 저장소로 사용하지 않습니다.

## 기준 자료

- 깨끗한 일본판 ROM: S25U 내부 저장공간/ROM 로컬 전용
- 진단 기준 패치: patch/Final_Conflict_Japan_to_Korean_v5.1.bps
- 외부 영어 참조: fcpatch_070706.ips, S25U 로컬 전용
- 압축 조사: analysis/compression_research.md
- 패치 구조: analysis/v5_1_patch_layout.md
- 문제 목록: docs/issues.md

v5.1은 최종판이 아니라 재작업용 진단 기준입니다.

## 기존 범위 기록

기존 보고서는 전체 1,492개, 번역 처리 103개, 미처리 1,389개, 위험 미처리 1,297개, 한글 글리프 168개라고 기록합니다. 단어 사전 확장이 검증되지 않은 결과이므로 완료율 근거로 쓰지 않습니다.

## 2026-07-29 완료 항목

1. BPS 크기, SHA-256과 소스/대상/패치 CRC 검증
2. BPS 액션 3,305개와 ROM 확장 구조 기록
3. 영어 IPS 크기, SHA-256과 288개 레코드 검증
4. Huffman 벡터 0x29C3F, 256개 엔트리와 221개 트리 확인
5. 독립 BPS/IPS/Huffman Python 파서와 합성 테스트 추가
6. ROM과 외부 IPS가 Git에 올라가지 않도록 규칙 강화
7. 한국어 v5.1 벡터를 0x80100에서 확인하고 51개 트리 전부 파싱
8. 한국어 심벌/트리 구간 0x80300..0x808D3 확정
9. 244엔트리 글꼴 페이지 매핑과 뱅크 0x22..0x5E 배치 확인
10. S25U 원클릭 검증 파이프라인과 실제 BPS 회귀 테스트 추가
11. 전체 v5.1 ROM의 코드 리터럴 및 2·3바이트 조회표 후보 자동 점수화 추가
12. 내 파일 앱에서 바로 보이는 reports/NEXT_STEP.txt 생성 경로 추가
13. S25U 첫 탐색에서 3바이트 110개, 2바이트 50개와 최상위 0x000B7D 관측
14. 상위 후보의 Z80 slot 가설과 emucap read breakpoint/매퍼 스냅샷 계획 자동 생성
15. 0x010000 후보를 과대평가한 0x4000/0x8000 제어 흐름 오탐을 격리하고 점수식 v2로 수정
16. 뱅크 리터럴 단독 출현과 슬롯별 Sega mapper 쓰기를 분리하고 점수식 v3 회귀 테스트 추가
17. ROM·대사·로컬 경로를 제외한 S25U 관측 요약의 GitHub 자동 게시 경로 추가
18. 0x000B7A/0x000B7B 시프트 해석을 정렬 클러스터로 묶고 0x000B7A..0x000C2E 통합 감시 범위 생성
19. 런타임 관측·진단·소비자 해석을 검증한 뒤 허용된 파일만 한 커밋으로 게시하는 S25U 묶음 게시 단계 추가
20. 표 범위 히트와 실제 압축 대상 주소 히트를 분리하고, 두 번째 히트의 논리 주소와 매퍼 뱅크가 모두 맞을 때만 정렬을 확정하도록 승격 조건 강화
21. ROM 없이 `한다`의 페이지 27 글리프와 `5F 03 0D 1F 04 C9` Huffman 39비트 왕복을 검증하는 fail-closed 사전검증 추가
22. schema v2 런타임 엔트리가 확정될 때만 깨끗한 원본에서 시험 ROM·로컬 IPS를 만드는 Expected Write/diff 감사 빌더 추가
23. S25U 첫 런타임 범위 히트가 슬롯 2의 실제 뱅크 2에서 발생해 물리 뱅크 0 조회표 증거가 아님을 확인하고, 매퍼 뱅크 불일치 히트를 거부한 뒤 탐색을 계속하도록 수정
24. 뱅크 불일치 오탐 제거 뒤 물리 0x000B7A..0x000C2E 후보가 1,680프레임 입력 구간에서 읽히지 않음을 확인하고, 직전 무히트 범위를 제외한 다음 두 bounded-decode 3바이트 후보군을 자동 순회하도록 확장
25. 물리 뱅크 0·6·16의 상위 3바이트 후보군 8개 논리 범위가 모두 무히트임을 확인하고, 최근 Git 이력의 음성 증거를 누적한 뒤 검증된 렌더러 호출 좌표 0x003FD5·0x03FFB2를 execute breakpoint로 역추적하는 단계 추가
26. 기존 렌더러 추적이 Start 입력으로 도입 장면을 건너뛴 경로 오류를 확인하고, 콜드 부팅 한 번에 여섯 후보를 동시에 감시하며 12,000프레임 동안 아무 입력 없이 attract intro를 기다리도록 수정
27. S25U 무입력 attract intro에서 0x5F 전용 페이지 렌더러 호출이 0회임을 확인하고, 더 앞선 공용 텍스트 디코더 0x003411의 세 매핑을 감시한 뒤 첫 히트부터 slot 1·2 ROM read를 최대 64개까지 매퍼 일치 물리 좌표로 수집하도록 전환
28. S25U에서 공용 텍스트 디코더도 12,000프레임 무입력 attract 경로에 나타나지 않음을 확인하고, 취소인 1번 버튼을 제거한 뒤 Start와 2번 확인 버튼으로 새 게임 스토리를 진행하는 경로로 교정
29. Start·2번 확인 경로 3,300프레임을 요청한 초기 무히트 결과를 기록하고, 검증되지 않은 0x003411 진입점 대신 물리 0x080100..0x0802FF 한국어 Huffman 벡터의 slot 1·2, mapper bank 0x20 실제 read를 직접 추적하도록 전환
30. 같은 요청 경로에서 Huffman 벡터 read가 없을 때 부팅·Start·확인 1/4/16회 화면 5개를 S25U에만 저장하고, GitHub에는 PNG 해시와 정지 판정만 게시하는 경로 진단을 추가
31. Gearsystem 3.9.14의 `debug_step_frame`가 완료가 아니라 요청 접수 직후 응답함을 소스와 단색 캡처로 확인했습니다. 초기 3,300프레임 무히트·화면 해시 결론을 폐기하고, `debug_get_status.paused`/breakpoint 완료 장벽과 새 증거 스키마로 전체 런타임 경로를 재검증하도록 수정했습니다.
32. 동기화된 첫 slot 0·bank 0 hit가 감시 범위 내부 PC 0x0B7B의 opcode fetch임을 확인했습니다. 실행 물리 PC가 감시 물리 범위와 겹치는 hit를 데이터 read로 승격하지 않고 해당 매핑을 제외한 다음 매핑을 계속 추적하도록 수정했습니다.
33. USB ADB로 최초 검증한 뒤 케이블 없이도 새 `origin/main` 커밋만 한 번씩 처리하는 S25U 자동실행기를 추가했습니다. canonical main·ROM 공유 저장공간·safe artifact allowlist를 벗어나거나 안전하지 않은 로컬 변경·커밋을 발견하면 중단하고, 동일 실패 커밋을 반복 실행하지 않습니다.
34. S25U 자동실행의 설치·시작·상태·로그·안전 중지를 한 관리 도구로 묶었습니다. 죽은 PID의 stale lock만 복구하고 살아 있는 프로세스와 경쟁하지 않으며, 내 파일 앱에서 확인할 `reports/AUTOPILOT_STATUS.txt`와 Termux:Boot 개인 실행기를 생성합니다.
35. 자동실행 첫 작업이 Gearsystem 준비·대상 식별을 모두 통과한 뒤 `runtime-command`에서 종료 코드 1을 게시했습니다. 경로·stderr를 공유하지 않고 실패 단계·종류·마지막 MCP 메서드만 schema v3 진단에 포함하도록 런타임 probe의 실패 영수증을 추가했습니다. 새 소스 커밋은 같은 S25U 자동실행에서 원인 분류를 다시 수집합니다.
36. 재수집 결과 실제 실패가 `candidate-probe/frame-step-timeout`임을 확인했습니다. proot의 S25U 실행을 PAL 실시간 속도로 가정한 8.6초 제한을 폐기하고, 180프레임은 최소 60초·240프레임은 63초를 허용하는 bounded 완료 장벽으로 수정했습니다.
37. 60초 제한에서도 같은 실패가 재현되어 Gearsystem 3.9.14 소스를 대조했습니다. 장거리 경로 전체의 CPU trace가 모든 Z80 명령을 기록하는 비용을 원인 경계로 보고, 첫 단계는 trace 없이 mapper 일치·실행 범위 비중첩 read hit만 수집하며 정확한 접근 명령은 확정 구간의 짧은 후속 replay로 분리했습니다.
38. CPU trace를 꺼도 60초 multi-frame 완료가 돌아오지 않아 Gearsystem의 pending frame·pause 구현을 추가 확인했습니다. 브레이크포인트 감시 중에는 취소할 수 없는 multi-frame 예약을 쓰지 않고, 1프레임마다 `debug_get_status.paused` 또는 breakpoint를 확인하는 정확하고 bounded한 경로로 교체했습니다.
39. S25U가 단일 프레임 장벽으로 3,300프레임 경로를 정상 완료해 시간초과를 해소했습니다. 현재 입력 경로의 상위 조회표 후보는 매퍼 일치 read가 없었으므로 반복하지 않고, BPS만으로 확인되는 0x0033FA..0x003405 패치 코드와 0x003432의 tree bank 0x20 리터럴을 근거로 0x33FA·0x3411·0x3431 execute 후보를 먼저 추적하도록 전환했습니다.
40. Start·2번 확인 3,300프레임에서 세 execute 후보가 모두 무히트임을 동기화된 S25U 실행으로 확인했습니다. 오프닝 소개가 무입력 대기에서 시작된다는 게임 진행 자료에 맞춰, 다음 실행은 동기화된 무입력 12,000프레임을 먼저 검사한 뒤 2번 확인과 1번 확인을 각각 별도 콜드 부팅으로 비교합니다.
41. 무입력·버튼 경로 매트릭스 첫 실행이 `runtime-command` 종료 코드 1로 끝났습니다. 전체 예외와 로컬 경로는 S25U에만 보존하고, renderer 단계도 기존 schema v3 실패 영수증을 사용해 실패 단계·종류·마지막 MCP 메서드만 다음 자동 결과에 게시하도록 보강했습니다.

## 현재 체크포인트

- 0x000B7A..0x000C2E 통합 범위 히트 뒤 실제 압축 대상 주소를 읽을 때의 매퍼 뱅크
- 한국어 문맥 0x00..0x20과 제어 심벌의 화면 의미
- And so began Mishaela's new ambition... 및 기존 한국어 문장의 정확한 엔트리 ID

조회표 없이 압축 뱅크의 모든 바이트를 시작점으로 읽는 방식은 거짓 양성이 많아 사용하지 않습니다.

## S25U 명령

~~~sh
cd ~/storage/shared/ShiningForceKR
git pull --ff-only
python tools/run_mobile_pipeline.py --rom "/storage/emulated/0/ROM/Shining Force Gaiden - Final Conflict (Japan).gg"
~~~

이 명령은 ROM과 보고서를 S25U 로컬의 build/ 및 reports/에만 생성합니다. 내 파일에서 ShiningForceKR/reports/NEXT_STEP.txt를 먼저 확인합니다. 원본 ROM은 덮어쓰지 않으며 Git 대상에서 제외됩니다.

USB ADB 최초 설정과 1회 실행 확인 뒤 케이블 없이 새 GitHub 커밋을
자동 처리하려면 `tools/manage_s25u_autopilot.sh install`을 사용합니다.
상태와 로그는 Termux 전용 `~/.local/state/shiningforcekr/`에 남고,
사용자용 상태 요약만 로컬 `reports/AUTOPILOT_STATUS.txt`에 생성됩니다.
ROM 경로와 상태 파일은 Git에 게시하지 않습니다.

캡처 없이 안전 요약을 GitHub에 공유할 때는
`--publish-safe-observation`을 붙입니다. 이 옵션은
`analysis/device/v5_1_latest_observation.json`만 검증·커밋·푸시하며,
ROM 바이트, 대사와 로컬 경로는 스키마에 포함할 수 없습니다.

## 다음 순서

1. 완료: S25U v5 전수 집계에서 0x000B7B가 58/60 종료·60/60 고유 대상으로 1바이트 시프트 대안보다 우세함을 기록했습니다.
2. 완료: 공식 Gearsystem 3.9.14 ARM64를 S25U 격리 환경에 설치했습니다.
3. 완료: 물리 뱅크 0·6·16의 정적 상위 조회표 후보를 slot 0/1/2에서 순차 추적했으나 현재 입력 구간의 뱅크 일치 read는 0회였습니다.
4. BPS에서 tree bank 0x20으로 패치된 디코더 영역의 0x33FA·0x3411·0x3431 execute 후보를 무입력 attract intro, 2번 확인, 1번 확인의 별도 콜드 부팅에서 감시합니다. 진입 직후에만 짧은 CPU trace와 slot 1·2 ROM read를 켜서 한국어 Huffman 벡터 물리 0x080100..0x0802FF의 실제 소비를 확인합니다.
5. 자동 hit resolver로 마지막 Z80 읽기 주소를 물리 표 바이트·정렬 후보·엔트리 번호·bounded decode에 연결합니다.
6. 확정 후보가 가리키는 압축 대상 주소에 두 번째 read breakpoint를 걸고 실제 매퍼 뱅크가 포인터의 뱅크와 일치할 때만 확정합니다.
7. 히트 PC와 0x87000 런타임의 호출·데이터 흐름을 연결해 조회표 전체를 확정합니다.
8. 완료: 첫 화면 경로 시험 표식 `한다`의 글리프·페이지 선택·Huffman 왕복을 ROM 없이 검증했습니다.
9. 준비 완료: 런타임 확정 엔트리에만 적용되는 무변경 왕복·Expected Writes·IPS 재적용 빌더를 연결했습니다.
10. S25U 런타임으로 실제 소비 엔트리와 매퍼 뱅크를 확정하고 조건 통과 시 시험 ROM을 자동 생성합니다.
11. 목표 인트로 문장과 기존 한국어 문장을 정확한 엔트리 ID로 재현합니다.
12. 콜드 부팅 기준으로 `한다` 자형과 SFKR-001부터 SFKR-007까지 에뮬레이터 검증합니다.

## 금지 사항

- 원본 ROM 덮어쓰기
- ROM 또는 미리 패치된 ROM 커밋
- 외부 영어 IPS 커밋
- 조회표와 사전이 불명확한 상태에서 대량 번역 삽입
- 정적 분석만으로 화면 문제 해결 선언
