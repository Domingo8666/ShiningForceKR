# ShiningForceKR

Sega Game Gear용 Shining Force Gaiden: Final Conflict (Japan) 한국어 패치 재작업 프로젝트입니다.

## 저장 원칙

- 기준 저장소: https://github.com/Domingo8666/ShiningForceKR
- 실제 ROM과 생성 ROM은 S25 Ultra 내부 저장공간에만 둡니다.
- PC 폴더는 기준 저장소나 작업 자료 보관소로 사용하지 않습니다.
- 원본 ROM, 생성 ROM, 세이브 상태, 외부 참조 IPS는 Git에 올리지 않습니다.
- GitHub에는 소스, 번역문, 분석 기록, 테스트, 배포 가능한 패치만 저장합니다.

## S25U 작업 경로

Termux 저장소:

~~~sh
cd ~/storage/shared/ShiningForceKR
git pull --ff-only
~~~

Android 내 파일 앱: 내부 저장공간/ShiningForceKR

원본 ROM은 현재 내부 저장공간/ROM에 그대로 두며 옮길 필요가 없습니다.

## 현재 기술 상태

- v5.1 BPS의 크기, 체크섬, 액션 구성과 ROM 확장 구간을 검증했습니다.
- 한국어 v5.1의 재배치 Huffman 벡터는 0x80100이며 51개 문맥 트리를 가집니다.
- 한국어 심벌/트리 데이터 0x80300..0x808D3과 244엔트리 글꼴 페이지 매핑을 독립 파서로 재현합니다.
- 기술 시험 문장 `한다`는 페이지 27의 0x1F·0x04 글리프를 사용하며, 심벌열 `5F 03 0D 1F 04 C9`가 한국어 Huffman 트리에서 39비트로 정확히 왕복됨을 ROM 없이 검증합니다.
- 이 문장은 화면 경로를 확인하기 위한 technical-poc-only 표식이며, 런타임 소비자·정확한 엔트리·Expected Writes·콜드 부팅 화면 증거 전에는 빌드 가능 상태가 아닙니다.
- 영어판 IPS의 별도 Huffman 벡터 0x29C3F에는 221개 트리가 있습니다.
- 전체 v5.1 ROM에서 코드 리터럴과 2·3바이트 조회표 후보를 자동 점수화합니다.
- 상위 후보의 가능한 Z80 버스 주소와 emucap read breakpoint 계획을 자동 생성합니다.
- 슬롯별 Sega mapper 레지스터 쓰기가 실제로 결합된 포인터 모양을 단순 뱅크 리터럴보다 우선합니다.
- 90% 이상 겹치는 같은 폭의 시프트 후보는 하나의 정렬 클러스터와 통합 감시 범위로 추적합니다.
- 상위 3바이트 조회표 후보 4개는 표본이 아닌 모든 엔트리를 디코드해 종료율, 길이 분포, 고유 대상 수와 대상 범위를 집계합니다.
- S25U 전수 집계에서 0x000B7B 정렬은 60개 중 58개가 제한 안에서 종료되고 고유 대상 60개를 유지해, 0x000B7A의 57/60·고유 대상 54개보다 우세합니다.
- 공식 Gearsystem ARM64와 MCP read breakpoint를 S25U의 격리된 Ubuntu 환경에서 실행하는 자동 추적 단계를 제공합니다.
- 표 범위가 읽힌 뒤 각 정렬 후보가 가리키는 압축 대상 주소를 같은 에뮬레이터 세션에서 다시 감시하고, 대상 주소와 매퍼 뱅크가 함께 일치해야 정렬을 확정합니다.
- 후보는 실행 중 소비 증거가 생기기 전까지 확정 조회표로 승격하지 않습니다.
- 조회표가 확정되기 전에는 기존 1,492개 추정 목록을 번역 완료 근거로 쓰지 않습니다.

근거는 analysis/compression_research.md, analysis/v5_1_patch_layout.md, analysis/v5_1_engine_layout.md 에 있습니다.

## S25U 자동 빌드와 다음 단계 분석

현재 ROM 위치에 맞춘 실행 명령입니다.

~~~sh
cd ~/storage/shared/ShiningForceKR
git pull --ff-only
python tools/run_mobile_pipeline.py --rom "/storage/emulated/0/ROM/Shining Force Gaiden - Final Conflict (Japan).gg"
~~~

이 명령은 원본/BPS/대상 CRC, 한국어 Huffman 블록과 글꼴 런타임을 검증하고 스크립트 소비 후보 탐색 및 emucap 실행 추적 계획 생성까지 이어서 수행합니다.

사진 대신 ROM 비포함 후보 요약을 GitHub에 자동 기록하려면 다음 옵션을
붙입니다. 게시 파일은 허용된 좌표·점수·매퍼 범위만 포함하며, ROM 바이트,
대사와 로컬 경로가 들어오면 게시를 거부합니다.

~~~sh
python tools/run_mobile_pipeline.py \
  --rom "/storage/emulated/0/ROM/Shining Force Gaiden - Final Conflict (Japan).gg" \
  --publish-safe-observation
~~~

결과는 `analysis/device/v5_1_latest_observation.json`에 커밋됩니다. 모바일
Git 인증이 아직 없으면 짧은 `SFKR safe observation` 결과까지는 터미널에
표시되고 Git 게시 단계에서 멈춥니다.

- build/Final_Conflict_Korean_v5.1.gg
- reports/NEXT_STEP.txt
- reports/v5_1_mobile_verification.md
- reports/v5_1_engine_report.md
- reports/v5_1_script_lookup_candidates.md
- reports/v5_1_emucap_trace_plan.md
- reports/v5_1_emucap_trace_plan.json
- reports/v5_1_test_phrase_plan.json
- reports/pipeline_status.json
- analysis/device/v5_1_latest_observation.json (`--publish-safe-observation` 사용 시)

내 파일 앱에서는 내부 저장공간 > ShiningForceKR > reports > NEXT_STEP.txt를 먼저 열면 됩니다. reports와 build는 S25U 로컬 전용이며 Git에 올라가지 않습니다.

ROM을 쓰지 않고 메모리 검증만 하려면 --no-rom-output을 붙입니다. 영어 참조 IPS가 없으면 그 단계만 skipped로 기록됩니다. 실행 추적으로 스크립트 소비자가 확정되기 전에는 translation_build_eligible을 false로 유지합니다.

## S25U 실제 읽기 추적

정적 후보를 실제 실행 읽기와 연결하려면 아래 명령을 한 번 실행합니다.
첫 실행은 S25U의 Termux 전용 공간에 Ubuntu와 공식 Gearsystem ARM64를
설치하므로 시간이 걸릴 수 있습니다. 다운로드한 Gearsystem 3.9.14
배포 파일은 고정 SHA-256으로 검증합니다.

~~~sh
cd ~/storage/shared/ShiningForceKR
git pull --ff-only
bash tools/run_s25u_runtime_stage.sh \
  --source-rom "/storage/emulated/0/ROM/Shining Force Gaiden - Final Conflict (Japan).gg"
~~~

원본 ROM과 생성 ROM은 `/storage/emulated/0`의 S25U 내부에 그대로 남습니다.
전체 CPU trace, 호출 스택과 로컬 경로는 Git에서 제외된
`reports/local/v5_1_gearsystem_probe.json`에만 저장합니다. GitHub에는
PC·매퍼 레지스터·범위·집계 개수만 허용하는
`analysis/device/v5_1_latest_runtime_observation.json`만 게시합니다.
첫 범위 히트만으로 번역 삽입을 허용하지 않고, 히트 PC를 정확한 엔트리와
bounded decode에 연결한 뒤 다음 게이트를 엽니다.

히트가 생기면 같은 wrapper가 로컬 trace의 마지막 메모리 읽기 명령을
제한된 Z80 주소 형식으로 판정하고, 접근한 물리 표 바이트를 정렬 후보의
엔트리 번호와 연결합니다. 이어서 각 후보 포인터의 압축 대상 주소에
두 번째 read breakpoint를 걸며, 실제로 읽힌 주소와 그 슬롯의 매퍼
뱅크가 포인터와 일치하고 제한 안에서 디코딩될 때만 소비 증거를
확정합니다. 정적 점수가 높은 시프트 정렬은 이 실행 증거를 대신하지
않습니다. 컨텍스트별 Huffman
경로를 다시 인코딩해 원래 비트열과 정확히 같은지도 함께 검증합니다.
GitHub에는 opcode,
엔트리 바이트와 디코딩 심벌을 제외한
`analysis/device/v5_1_latest_consumer_resolution.json`만 게시하며,
왕복 인코딩 전까지 `translation_build_eligible`은 false입니다.

schema v2 런타임 증거가 한 엔트리를 확정하면 같은 wrapper가 원본 ROM과
v5.1 BPS에서 기준 이미지를 메모리로 다시 만들고, `한다`가 기존 엔트리의
확인된 비트·바이트 경계 안에 들어가는지 검사합니다. 공유 타깃, 인접
엔트리 겹침, 원본 왕복 불일치, 예상 원본 바이트 불일치가 하나라도 있으면
아무 산출물도 만들지 않습니다. 모두 통과하면 다음 S25U 로컬 파일만
생성합니다.

- `build/Final_Conflict_Korean_test_phrase.gg`
- `build/Final_Conflict_Korean_test_phrase_overlay.ips`
- `reports/local/v5_1_test_patch_build.json`

모든 변경은 불변 기준 이미지를 대상으로 한 Expected Write로 먼저
검증하고, 최종 diff와 IPS 재적용 결과가 같을 때만 기록합니다. 이
산출물은 technical-poc-only이며 게임 화면에서 `한다`의 자형과 주변
동작을 콜드 부팅으로 확인하기 전에는 배포 패치나 번역 완료 근거가
아닙니다.

테스트 ROM이 생성되면 wrapper는 콜드 부팅으로 확정 엔트리의 압축
데이터 read를 다시 관측하고 매퍼 뱅크를 대조합니다. 일치할 때만
1·8·30·90프레임 뒤 화면을 다음 S25U 로컬 폴더에 PNG로 저장합니다.

- `evidence/local/v5_1_test_phrase/`
- `reports/local/v5_1_test_display_capture.json`

PNG와 로컬 경로는 Git에서 제외합니다. GitHub에는 ROM·화면 없이 빌드
해시, read·뱅크 일치 여부, PNG 해시·크기와 사람 시각 확인 대기 상태만
`analysis/device/v5_1_latest_display_capture.json`에 게시합니다. 자동
캡처는 저장→읽기→화면 후보를 연결하지만, 실제 자형·위치·주변 UI의
정상 여부는 사람이 S25U 로컬 PNG를 확인해야 통과합니다.

설치 또는 MCP 시작이 중단되면 wrapper가 경로·로그·ROM 정보를 제외한
불리언 점검 결과만
`analysis/device/v5_1_latest_runtime_diagnostic.json`에 게시합니다.
Gearsystem이 응답하지 않을 때도 30초 제한으로 종료해 실패 단계를 남깁니다.
관측·해석·진단 파일은 각각 검증한 뒤 허용된 경로만 한 번에 커밋하며,
모바일 작업트리의 다른 로컬 파일은 수정하거나 커밋하지 않습니다.

## 안전 규칙

- 내부 저장공간/ROM의 원본 파일은 절대 덮어쓰지 않습니다.
- 생성 ROM은 build/에만 씁니다.
- 변경 전후 해시를 기록합니다.
- 시험 ROM의 모든 변경은 겹치지 않는 Expected Write와 전체 diff로 검산합니다.
- 바이트 모양 후보, 정적 분석, 실제 에뮬레이터 소비 증거를 구분합니다.
- 모바일 공유 데이터는 고정된 안전 스키마를 통과한 필드만 GitHub에 게시합니다.
- 해결되지 않은 문제를 해결됐다고 보고하지 않습니다.
