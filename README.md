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
- 영어판 IPS의 별도 Huffman 벡터 0x29C3F에는 221개 트리가 있습니다.
- 전체 v5.1 ROM에서 코드 리터럴과 2·3바이트 조회표 후보를 자동 점수화합니다.
- 상위 후보의 가능한 Z80 버스 주소와 emucap read breakpoint 계획을 자동 생성합니다.
- 슬롯별 Sega mapper 레지스터 쓰기가 실제로 결합된 포인터 모양을 단순 뱅크 리터럴보다 우선합니다.
- 90% 이상 겹치는 같은 폭의 시프트 후보는 하나의 정렬 클러스터와 통합 감시 범위로 추적합니다.
- 상위 3바이트 조회표 후보 4개는 표본이 아닌 모든 엔트리를 디코드해 종료율, 길이 분포, 고유 대상 수와 대상 범위를 집계합니다.
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
- reports/pipeline_status.json
- analysis/device/v5_1_latest_observation.json (`--publish-safe-observation` 사용 시)

내 파일 앱에서는 내부 저장공간 > ShiningForceKR > reports > NEXT_STEP.txt를 먼저 열면 됩니다. reports와 build는 S25U 로컬 전용이며 Git에 올라가지 않습니다.

ROM을 쓰지 않고 메모리 검증만 하려면 --no-rom-output을 붙입니다. 영어 참조 IPS가 없으면 그 단계만 skipped로 기록됩니다. 실행 추적으로 스크립트 소비자가 확정되기 전에는 translation_build_eligible을 false로 유지합니다.

## 안전 규칙

- 내부 저장공간/ROM의 원본 파일은 절대 덮어쓰지 않습니다.
- 생성 ROM은 build/에만 씁니다.
- 변경 전후 해시를 기록합니다.
- 바이트 모양 후보, 정적 분석, 실제 에뮬레이터 소비 증거를 구분합니다.
- 모바일 공유 데이터는 고정된 안전 스키마를 통과한 필드만 GitHub에 게시합니다.
- 해결되지 않은 문제를 해결됐다고 보고하지 않습니다.
