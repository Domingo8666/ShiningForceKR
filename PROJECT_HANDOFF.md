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

## 현재 체크포인트

- 0x000B7A..0x000C2E 통합 범위를 읽는 실제 소비 코드와 실행 중 뱅크 상태
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

캡처 없이 안전 요약을 GitHub에 공유할 때는
`--publish-safe-observation`을 붙입니다. 이 옵션은
`analysis/device/v5_1_latest_observation.json`만 검증·커밋·푸시하며,
ROM 바이트, 대사와 로컬 경로는 스키마에 포함할 수 없습니다.

## 다음 순서

1. 완료: S25U v5 전수 집계에서 0x000B7B가 58/60 종료·60/60 고유 대상으로 1바이트 시프트 대안보다 우세함을 기록했습니다.
2. 공식 Gearsystem 3.9.14 ARM64를 S25U 격리 환경에 설치하고 slot 0/1/2 범위를 순차 자동 추적합니다.
3. 첫 read breakpoint 히트의 PC, physical PC, 매퍼 레지스터, Z80 레지스터와 로컬 trace를 기록합니다.
4. 히트 PC와 0x87000 런타임의 호출·데이터 흐름을 연결해 정확한 접근 엔트리와 조회표를 확정합니다.
5. 한국어 문맥 심벌과 글꼴 페이지 선택 규칙을 엔트리별로 연결합니다.
6. 목표 인트로 문장과 기존 한국어 문장을 정확한 엔트리 ID로 재현합니다.
7. 왕복 인코딩과 사람 검수 뒤 첫 한글 문장 삽입을 재개합니다.
8. 콜드 부팅 기준으로 SFKR-001부터 SFKR-007까지 에뮬레이터 검증합니다.

## 금지 사항

- 원본 ROM 덮어쓰기
- ROM 또는 미리 패치된 ROM 커밋
- 외부 영어 IPS 커밋
- 조회표와 사전이 불명확한 상태에서 대량 번역 삽입
- 정적 분석만으로 화면 문제 해결 선언
