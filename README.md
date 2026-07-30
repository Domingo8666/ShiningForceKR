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
- 기술 시험 문장 `한다`는 Galmuri7과 픽셀 일치하는 페이지 6의 0x11·0x04 글리프를 사용하며, 기본 심벌열 `5F 02 08 11 04 C9`가 한국어 Huffman 트리에서 31비트로 정확히 왕복됨을 ROM 없이 검증합니다.
- DE=2에서 포인터 0x43DE를 고르는 디코더 진입을 확인했고, ROM 바이트 없는 64명령 레지스터 추적으로 B=147의 의미도 확정했습니다. `INC B` 뒤 `DJNZ` 루프는 147개의 `길이 1바이트 + 데이터 N바이트` 레코드를 건너뜁니다. 이전 목표 0x44B1은 대사 payload가 아니라 중간 길이 바이트였으므로 제외했습니다. 현재 자동 빌더는 147개 레코드를 정적으로 다시 순회한 뒤 선택된 148번째 payload만 무변경 왕복·Expected Write 검사 후 시험합니다.
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

휴대폰에서 실행할 명령과 사진을 올려야 하는 경우는
`docs/S25U_EASY_GUIDE.md`에 짧은 순서로 정리했습니다. 자동실행기의
기본 GitHub 확인 주기는 30초이며, 기준·시험 화면이 완전히 같은 후보는
한 작업에서 최대 8개까지 자동으로 다음 후보로 넘어갑니다. 시험 화면은
검증된 Galmuri7 `한다` 두 글자의 정확한 8×8 잉크 마스크도 함께 검사합니다.
화면이 달라져도 이 표식이 없으면 기계적으로 자동 탈락시키며, 기준 화면에
없던 정확한 표식이 검출될 때만 사람의 최종 자형·문맥 확인을 기다립니다.

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
런타임 명령이 중간에 실패하면 전체 오류문·로컬 경로는 계속 S25U에만
남기고, 실패 단계·종류·마지막 MCP 메서드의 고정 토큰만
`analysis/device/v5_1_latest_runtime_diagnostic.json` schema v3에
게시합니다. 따라서 자동실행 재시도 결과로 다음 수정 지점을 구분할 수
있지만 비공개 ROM 경로나 에뮬레이터 stderr는 GitHub에 노출되지 않습니다.
첫 범위 히트만으로 번역 삽입을 허용하지 않고, 히트 PC를 정확한 엔트리와
bounded decode에 연결한 뒤 다음 게이트를 엽니다.
같은 논리 주소라도 슬롯에 매핑된 물리 ROM 뱅크가 추적 계획과 다르면
로컬 오탐 기록으로만 남기고, 뱅크가 일치하는 다음 히트를 계속 찾습니다.
한 실행에서 유효 히트가 없으면 게시된 무히트 범위를 다음 실행에서
자동 제외하고, 제한 디코딩이 가능한 다음 3바이트 후보군 두 개를
순위대로 추적합니다. 따라서 같은 정적 1위만 반복해서 검사하지 않습니다.
Git 이력의 최근 무히트 범위를 누적한 뒤 상위 후보군을 모두 소진하면,
정적 포인터 모양 탐색을 더 넓히지 않습니다. 대신 v5.1 패치에서 검증한
한글 렌더러 호출 좌표를 execute breakpoint로 추적해 실제 소비 경로에서
스크립트 쪽으로 거슬러 올라갑니다. 무입력 attract intro에서는 0x5F 전용
페이지 렌더러와 추정 텍스트 디코더 0x003411이 모두 실행되지 않았고,
Start와 2번 확인 버튼을 요청한 초기 3,300프레임 무히트 결과는
Gearsystem 3.9.14가 `debug_step_frame` 실행 완료 전 요청 접수 응답을
돌려준다는 사실이 확인되어 폐기했습니다. 모든 프레임 구간은
`debug_get_status.paused` 또는 breakpoint 정지를 완료 장벽으로 사용해
다시 검증합니다.
완료 장벽으로 처음 잡힌 slot 0·bank 0 hit의 PC가 감시 범위 안
`0x0B7B`였으므로 데이터 소비가 아니라 opcode fetch로 판정했습니다.
이제 매퍼 일치뿐 아니라 실행 물리 PC가 감시 물리 범위와 겹치지 않고,
로컬 trace에서 실제 메모리 피연산자 read를 복원할 수 있을 때만 안전
runtime hit로 승격합니다.
0x003411 하나만 디코더 진입점으로 확정하지 않습니다. 다만 v5.1 BPS만으로
복원되는 0x0033FA..0x003405 패치 코드와 0x003432의 tree bank 0x20
리터럴을 확인했으므로, 0x33FA·0x3411·0x3431 execute 후보를 동시에
감시합니다. 오프닝 소개가 시작되는 무입력 12,000프레임을 먼저 검사하고,
Start 뒤 2번 확인과 1번 확인 경로도 각각 별도 콜드 부팅으로
3,300프레임씩 실행해 버튼 의미를 자동 비교합니다. 진입 전에는 장거리 CPU trace를 끄고, 후보가 실행된 직후에만
짧은 trace와 slot 1·2 ROM read를 켭니다. 이어서 검증된 한국어 Huffman
벡터 물리 0x080100..0x0802FF가 mapper bank 0x20으로 매핑된 실제 read를
직접 추적합니다. 히트 직후
ROM data read를 최대 64개의 고유 물리 좌표로 수집해 한국어
Huffman 벡터·트리 접근과 압축 스트림 후보를 구분합니다. 전체 trace와 경로는 S25U 로컬에만
두고 GitHub에는 호출 좌표·논리 주소·매퍼·레지스터 집계만 다음 파일로
게시합니다.

동기화된 무입력 attract intro에서 0x33FA execute hit와 PC 0x3406의
slot 1·bank 8 source-region read를 확인했습니다. 첫 64개가 모두 원본
영역 읽기여서, 후속 실행은 source-region 표본을 8개로 제한하되 최대
1,024개 read를 계속 따라가 bank 0x20 Huffman 벡터·트리 접근을 우선
보존했습니다. 그 결과 벡터 0x0802B6·0x0801BE·0x08010E와 관련 트리를
mapper bank 0x20에서 실제로 읽는 경로를 확인했습니다. 다음 실행은
원시 opcode를 S25U 로컬에만 두고 `hl-indirect`, `absolute-word` 같은
고정 operand-kind 토큰만 게시해 압축 stream과 조회 경계를 연결합니다.

- `analysis/device/v5_1_latest_renderer_observation.json`
- `analysis/device/v5_1_latest_decoder_stream_resolution.json`

실제 인트로에서 읽힌 source-region 시작점은 BPS 자체로 복원되는 한국어
Huffman 데이터와 제한 디코딩·재인코딩합니다. 종료 심벌까지 정확히
왕복하고 다음 런타임 시작점을 침범하지 않으며 사람 검토에서 기각되지
않은 첫 스트림을 기술 시험 문장 빌더에 전달합니다. 이 경로는 정적
조회표 모양을 가정하지 않으며,
시험 ROM과 PNG는 계속 S25U 로컬에만 둡니다.

첫 자동 실행에서 시험 ROM과 IPS 생성은 통과했습니다. 화면 캡처가 목표
논리 주소의 mapper bank 7 선행 히트에서 멈춘 것을 확인했으므로, 이후
실행은 bank 8과 검증된 디코더 PC가 함께 일치하지 않는 히트를 한 명령
넘긴 뒤 같은 breakpoint를 다시 설정합니다.

bank 8·물리 0x0203DE와 0x0203E8에서 얻은 화면은 초상·대화창·주변
한국어와 입력 뒤 화면 전이를 유지했지만 시험 문구 `한다`를 표시하지
않았습니다. source-region 표본을 32개로 늘려 18개 스트림을 수집한 뒤
시험한 0x020447도 같은 결과여서 세 후보를 사람 검토 실패로 누적
기록했습니다. 이어서 시험한 97비트 스트림 0x020462도 기존 대사만
표시해 네 번째로 기각했습니다. 다음 자동실행은 시험 문장 39비트를
수용하는 왕복 정확한 41비트 스트림 0x020473을 시험합니다. 캡처 픽셀,
대사와 로컬 경로는 GitHub에 게시하지 않습니다.

이 경로에서 벡터 read가 없으면 같은 wrapper가 부팅 대기, Start 직후,
1·4·16번째 2번 확인 직후 화면을 다음 S25U 로컬 폴더에 PNG로 저장합니다.

- `evidence/local/v5_1_story_route/`
- `reports/local/v5_1_story_route_capture.json`

GitHub에는 PNG가 아니라 단계 이름, 누적 프레임·입력 수, 화면 크기와
PNG SHA-256만 `analysis/device/v5_1_latest_route_capture.json`에 게시합니다.
마지막 두 화면의 해시가 같으면 자동 입력이 안정된 한 화면에서 멈춘
것으로만 판정합니다. 화면이 이름 입력, 메뉴 또는 스토리인지 같은 의미
판정은 로컬 PNG를 사람이 확인하기 전까지 확정하지 않습니다.

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
1·8·30·90프레임 뒤 화면과 A 버튼 입력 60프레임 뒤 화면을 다음 S25U
로컬 폴더에 PNG로 저장합니다.

- `evidence/local/v5_1_test_phrase/`
- `reports/local/v5_1_test_display_capture.json`

기준·시험 화면에 픽셀 차이가 있으면 변경 픽셀이 가장 많은 짝과 진행 후
화면을 SHA-256으로 다시 확인한 뒤 아래 폴더에도 쉬운 이름으로 복사합니다.

- `reports/HUMAN_REVIEW/1_BASELINE.png`
- `reports/HUMAN_REVIEW/2_TEST.png`
- `reports/HUMAN_REVIEW/3_AFTER_ADVANCE.png`
- `reports/HUMAN_REVIEW/README.txt`

PNG와 로컬 경로는 Git에서 제외합니다. GitHub에는 ROM·화면 없이 빌드
해시, read·뱅크 일치 여부, PNG 해시·크기와 사람 시각 확인 대기 상태만
`analysis/device/v5_1_latest_display_capture.json`에 게시합니다. 자동
캡처는 저장→읽기→화면 후보를 연결하지만, 실제 자형·위치·주변 UI의
정상 여부는 사람이 S25U 로컬 PNG를 확인해야 통과합니다.

현재 확정된 길이 접두 엔트리에서는 진행 후 시험 화면에서 기술 표식
`한다`가 기준판 0회·시험판 1회 검출됐고, 사람 검토로 초상·대화창과
주변 글자의 정상 표시도 통과했습니다. 최신 시험 화면 1장은
`analysis/device/v5_1_latest_progress_preview.png`에 계속 교체 게시하며,
사진 게시 뒤에도 자동작업은 중단하지 않습니다. 다음 실행은 로컬 빌드
보고서의 엔트리 경계·무변경 왕복과 이 화면 증거를 다시 묶어
`analysis/device/v5_1_latest_visible_entry_proof.json`으로 게시한 뒤
다중 글자 PoC로 확장합니다. 이 단계도 아직 배포용 번역 빌드는 아닙니다.

확정 증거의 엔트리는 16바이트·100비트 예산이며, 다음 자동 빌드는
같은 페이지에서 픽셀이 확인된 네 글자 `시험한다`를 사용합니다. 기본
44비트 문구에 화면에 그려지지 않는 페이지 선택 토큰만 더해 기존과
정확히 같은 100비트를 만들고, 같은 콜드 부팅 경로에서 새 진행 PNG를
게시합니다. 새 사진은 먼저 GitHub에 안전 커밋하고 같은 자동실행 안에서
기준판 캡처·픽셀 비교를 계속하므로, 사진 보고 때문에 검증이 멈추지
않습니다.

S25U 실기 결과 `시험한다`의 네 글자 연속 자형이 진행 후 화면 좌표
(24, 112)에서 정확히 1회 검출됐습니다. 기준판의 `한다` 접미 표식은
0회, 시험판은 1회였고 초상·대화창·주변 글자도 정상 판정을 유지했습니다.
이 결과는 `analysis/device/v5_1_latest_poc_expansion_proof.json`에
빌드·PNG·엔트리 해시와 함께 묶이며, 다음 자동 단계는 이 가시 레코드의
로컬 스크립트 추출과 무변경 왕복입니다.

가시 원본 레코드의 로컬 추출도 통과했습니다. 16바이트 저장공간에서
19심벌·100비트를 사용하고 종료자는 정확히 하나이며, 재인코딩한
100비트가 원본과 완전히 같습니다. 남은 28비트와 원문 심벌은
로컬 전용이고, GitHub에는
`analysis/device/v5_1_latest_visible_script_roundtrip.json`의 집계와
왕복 판정만 게시합니다.

다음 자동 단계는 이 레코드가 선택된 정확한 디코더 전달 지점에서
두 번째 프레임 경계까지만 Gearsystem trace를 제한적으로 켜고 Game Gear
VDP 데이터·제어 포트 출력을 수집합니다. 최초 바깥 호출 복귀까지의
7개 명령에서는 출력이 없었고, 첫 프레임 후반의 렌더러 제어 출력 뒤
데이터 전달이 남았으므로 두 프레임을 상한으로 확장했으며,
심벌, 명령어, 포트 값과 원시 trace는
`reports/local/`에만 남기고, GitHub에는
`analysis/device/v5_1_latest_renderer_output_trace.json`의 출력 횟수와
소비 경로 판정만 게시합니다. 단순히 같은 프레임에 있던 화면 갱신은
승인하지 않고, 확정된 bank 0x21의 0x7000..0x730B·0x7A00..0x7A9D
한국어 렌더러 안에서 발생한 VDP 제어 출력 뒤 같은 제한 프레임에서
실제 VDP 데이터 출력이 이어진 경우만 소비 경로로 승인합니다.
이 결과로 원문 심벌과 실제 화면 글리프를
차례로 정렬하며, 정렬이 끝나기 전에는 배포용 번역 빌드를 허용하지
않습니다.

0x33FA 디코더 경로의 캡처에서는 목표 read 순간의 DE와 고정
`0x3FE8 + DE` 포인터를 기준 ROM에서 다시 대조합니다. 현재 포인터와
다음 포인터가 목표 stream을 실제로 둘러쌀 때만 블록 엔트리 번호와
블록 내 오프셋을 경로 없는 안전 메타데이터로 게시합니다.

설치 또는 MCP 시작이 중단되면 wrapper가 경로·로그·ROM 정보를 제외한
불리언 점검 결과만
`analysis/device/v5_1_latest_runtime_diagnostic.json`에 게시합니다.
Gearsystem이 응답하지 않을 때도 30초 제한으로 종료해 실패 단계를 남깁니다.
관측·해석·진단 파일은 각각 검증한 뒤 허용된 경로만 한 번에 커밋하며,
모바일 작업트리의 다른 로컬 파일은 수정하거나 커밋하지 않습니다.

## S25U 케이블 분리 후 자동실행

USB ADB로 최초 설정과 1회 실행을 확인한 뒤에는 다음 자동실행기를
Termux에서 설치하고 계속 실행할 수 있습니다.

~~~sh
bash tools/manage_s25u_autopilot.sh install \
  --source-rom "/storage/emulated/0/ROM/Shining Force Gaiden - Final Conflict (Japan).gg"
~~~

설치 명령은 중복 프로세스를 막고 현재 작업을 백그라운드에서 시작하며,
Termux:Boot용 개인 실행기도 `~/.termux/boot/`에 설치합니다. 자동작업
상태는 내 파일 앱의 `ShiningForceKR/reports/AUTOPILOT_STATUS.txt`에서
확인할 수 있습니다. 상태 갱신과 안전 중지는 다음 명령을 사용합니다.

~~~sh
bash tools/manage_s25u_autopilot.sh status
bash tools/manage_s25u_autopilot.sh stop
~~~

자동실행기는 30초마다 canonical `origin/main`을 확인하고, 아직 처리하지
않은 새 커밋이 있을 때만 전체 S25U 런타임 단계를 한 번 실행합니다.
실패 결과도 검증된 safe runtime bundle로 게시한 뒤 같은 커밋을 반복
실행하지 않으므로 배터리와 Git 이력을 불필요하게 소모하지 않습니다.
원본 ROM과 생성 ROM은 S25U 공유 저장공간에만 남고, 자동 Git 쓰기는
고정 스키마를 통과한 safe artifact 경로로만 제한됩니다. 다른 tracked 변경, 다른
브랜치·원격 저장소 또는 안전하지 않은 로컬 커밋을 발견하면 자동실행을
중단합니다.

상태와 로그는 Git 밖의 Termux 전용 경로
`~/.local/state/shiningforcekr/`에 저장합니다. 자동실행을 안전하게
멈추려면 그 폴더에 `STOP` 파일을 만들면 됩니다. 케이블 제거 가능 여부는
최초 `--force --once` 실행과 GitHub 게시 확인 뒤 판정합니다. Termux가
강제 종료될 수 있으므로 Android 배터리 최적화 제외가 필요합니다.
재부팅 뒤 자동 시작은 Termux:Boot 앱이 설치되어 있고 Android에서 한 번
직접 실행된 경우에만 동작합니다. 관리 도구가 실행기 파일을 설치했다는
사실만으로 Termux:Boot 앱 설치·최초 실행까지 완료됐다고 판정하지 않습니다.

## 안전 규칙

- 내부 저장공간/ROM의 원본 파일은 절대 덮어쓰지 않습니다.
- 생성 ROM은 build/에만 씁니다.
- 변경 전후 해시를 기록합니다.
- 시험 ROM의 모든 변경은 겹치지 않는 Expected Write와 전체 diff로 검산합니다.
- 바이트 모양 후보, 정적 분석, 실제 에뮬레이터 소비 증거를 구분합니다.
- 모바일 공유 데이터는 고정된 안전 스키마를 통과한 필드만 GitHub에 게시합니다.
- 해결되지 않은 문제를 해결됐다고 보고하지 않습니다.
