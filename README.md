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
- 영어판 IPS의 Huffman 벡터 위치 0x29C3F와 256개 엔트리를 확인했습니다.
- 221개 트리가 존재하고 35개가 비어 있음을 독립 파서로 재현합니다.
- 0xC9는 시작/종료 심벌 후보입니다. 실제 스크립트 조회표와 단어 사전은 아직 확인 중입니다.
- 목표 문장 And so began Mishaela's new ambition... 은 조회표와 사전 검증 전까지 완료로 표시하지 않습니다.

근거는 analysis/compression_research.md 와 analysis/v5_1_patch_layout.md 에 있습니다.

## 모바일 검증 순서

1. 도구 테스트

~~~sh
python -m unittest discover -s tests -v
~~~

2. 영어 참조 IPS 받기 및 검증

~~~sh
python tools/fetch_fc_english_patch.py
~~~

3. 영어판 Huffman 트리 검증

~~~sh
python tools/sfgfc_huffman.py stats
~~~

4. 깨끗한 일본판 ROM으로 v5.1 검증 및 로컬 빌드

~~~sh
python tools/analyze_v5_1.py \
  --rom original/원본파일.gg \
  --output build/Final_Conflict_Korean_v5.1.gg \
  --report analysis/local_v5_1_diff_report.md
~~~

원본이 정확한 파일이 아니면 도구가 중단됩니다. 생성 ROM은 Git에서 제외됩니다.

## 안전 규칙

- original/ 파일은 절대 덮어쓰지 않습니다.
- 생성 ROM은 build/에만 씁니다.
- 변경 전후 해시를 기록합니다.
- 정적 분석과 실제 에뮬레이터 검증을 구분합니다.
- 해결되지 않은 문제를 해결됐다고 보고하지 않습니다.
