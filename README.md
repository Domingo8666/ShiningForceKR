# ShiningForceKR

Sega Game Gear용 Shining Force Gaiden: Final Conflict (Japan) 한국어 패치 재작업 프로젝트입니다.

## 저장 원칙

- 기준 저장소: https://github.com/Domingo8666/ShiningForceKR
- 실제 ROM과 생성 ROM은 S25 Ultra의 내부 저장공간/ShiningForceKR 에만 둡니다.
- PC 폴더는 기준 저장소나 작업 자료 보관소로 사용하지 않습니다.
- 원본 ROM, 생성 ROM, 세이브 상태, 외부 참조 IPS는 Git에 올리지 않습니다.
- GitHub에는 소스, 번역문, 분석 기록, 테스트, 배포 가능한 패치만 저장합니다.

## S25U 작업 경로

Termux:

~~~sh
cd ~/storage/shared/ShiningForceKR
git pull --ff-only
~~~

Android 내 파일 앱: 내부 저장공간/ShiningForceKR

## 현재 기술 상태

- v5.1 BPS의 크기, 체크섬, 액션 구성과 ROM 확장 구간을 검증했습니다.
- 한국어 v5.1의 재배치 Huffman 벡터는 0x80100이며 51개 문맥 트리를 가집니다.
- 한국어 심벌/트리 데이터 0x80300..0x808D3과 244엔트리 글꼴 페이지 매핑을 독립 파서로 재현합니다.
- 영어판 IPS의 별도 Huffman 벡터 0x29C3F에는 221개 트리가 있습니다.
- 실제 스크립트 조회표와 토큰 의미는 아직 소비 코드에서 확인 중입니다.
- 조회표가 확정되기 전에는 임의 시작점 디코딩이나 기존 1,492개 추정 목록을 번역 완료 근거로 쓰지 않습니다.

근거는 analysis/compression_research.md, analysis/v5_1_patch_layout.md, analysis/v5_1_engine_layout.md 에 있습니다.

## S25U 자동 준비와 검증

내부 저장공간/ShiningForceKR에서 원본 파일명만 맞춰 한 번 실행합니다.

~~~sh
cd ~/storage/shared/ShiningForceKR
git pull --ff-only
python tools/run_mobile_pipeline.py --rom "original/원본파일.gg"
~~~

이 명령은 원본과 BPS 식별, 대상 CRC, 한국어 Huffman 블록, 글꼴 런타임을 검증하고 다음 로컬 결과를 만듭니다.

- build/Final_Conflict_Korean_v5.1.gg
- analysis/local/v5_1_mobile_verification.md
- analysis/local/v5_1_engine_report.md
- analysis/local/pipeline_status.json

ROM을 쓰지 않고 메모리 검증만 하려면 --no-rom-output을 붙입니다. 영어 참조 IPS가 없으면 그 단계만 skipped로 기록되며, python tools/fetch_fc_english_patch.py로 받은 뒤 다시 실행할 수 있습니다. 스크립트 조회표와 토큰 의미가 확정되기 전에는 파이프라인이 translation_build_eligible을 false로 유지합니다.

## 안전 규칙

- original/ 파일은 절대 덮어쓰지 않습니다.
- 생성 ROM은 build/에만 씁니다.
- 변경 전후 해시를 기록합니다.
- 정적 분석과 실제 에뮬레이터 검증을 구분합니다.
- 해결되지 않은 문제를 해결됐다고 보고하지 않습니다.
