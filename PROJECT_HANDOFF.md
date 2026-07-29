# Shining Force Gaiden: Final Conflict 한국어 패치 인수인계

## 대상과 저장 위치

- 플랫폼: Sega Game Gear
- 게임: Shining Force Gaiden: Final Conflict (Japan)
- 메가 CD판이 아닙니다.
- 기준 저장소: https://github.com/Domingo8666/ShiningForceKR
- ROM 작업 위치: S25U 내부 저장공간/ShiningForceKR
- PC는 프로젝트 자료 저장소로 사용하지 않습니다.

## 기준 자료

- 깨끗한 일본판 ROM: S25U original/ 로컬 전용
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

## 현재 체크포인트

- 실제 스크립트 조회표와 뱅크 선택 규칙
- 0x80 이상 단어 사전 확장
- And so began Mishaela's new ambition... 의 ROM 기반 디코딩

조회표 없이 압축 뱅크의 모든 바이트를 시작점으로 읽는 방식은 거짓 양성이 많아 사용하지 않습니다.

## S25U 명령

~~~sh
cd ~/storage/shared/ShiningForceKR
git pull --ff-only
python -m unittest discover -s tests -v
python tools/fetch_fc_english_patch.py
python tools/sfgfc_huffman.py stats
python tools/analyze_v5_1.py \
  --rom original/원본파일.gg \
  --output build/Final_Conflict_Korean_v5.1.gg \
  --report analysis/local_v5_1_diff_report.md
~~~

마지막 명령의 원본 파일명만 실제 이름으로 바꿉니다. 해시가 다르면 중단됩니다.

## 다음 순서

1. S25U에서 검증된 v5.1 대상 ROM과 로컬 보고서를 생성합니다.
2. 소비 코드를 역추적해 조회표를 확정합니다.
3. 단어 사전을 추출하고 토큰을 확장합니다.
4. 목표 인트로 문장을 ROM에서 정확히 디코딩합니다.
5. 왕복 인코딩 검증 뒤 한국어 삽입을 재개합니다.
6. 콜드 부팅 기준으로 SFKR-001부터 SFKR-007까지 에뮬레이터 검증합니다.

## 금지 사항

- 원본 ROM 덮어쓰기
- ROM 또는 미리 패치된 ROM 커밋
- 외부 영어 IPS 커밋
- 조회표와 사전이 불명확한 상태에서 대량 번역 삽입
- 정적 분석만으로 화면 문제 해결 선언
