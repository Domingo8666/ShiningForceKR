# Shining Force Gaiden - Final Conflict 한국어 패치 인수인계

## 대상
- 플랫폼: Sega Game Gear
- 게임: Shining Force Gaiden - Final Conflict (Japan)
- 메가 CD판이 아님

## 확보된 기준 자료
- clean Japanese ROM: `original/`
- 현재 기준 패치: `patch/Final_Conflict_Japan_to_Korean_v5.1.bps`
- 재작업 상태 문서: `docs/korean_patch_rework_status.md`
- 번역 범위 보고서: `docs/korean_patch_coverage_report.txt`

## 현재 알려진 범위
- 전체 스크립트 엔트리: 1492
- 번역 처리 기록: 103
- 미처리 기록: 1389
- 위험 미처리 기록: 1297
- 사용된 한글 글리프 슬롯 기록: 168

## 기존 테스트에서 확인된 문제
1. 대사 전환 시 검은 깜빡임
2. A 버튼으로 대사를 넘길 때 이전 글자나 잘못된 한글이 순간적으로 섞임
3. 대사 진행 역삼각형 표시 타이밍 이상
4. `지누구그` 같은 깨진 문자열
5. 부자연스러운 번역과 상황에 맞지 않는 단어
6. 세이브 스테이트의 이전 VRAM·폰트 상태가 테스트를 방해할 가능성
7. 대사창 테두리와 주변 그래픽은 손상되면 안 됨

## 재작업 문서가 제시한 안전한 기반
1. 깨끗한 일본판 ROM
2. 알려진 영어 IPS 패치 `fcpatch_070706.ips`
3. 영어 패치의 렌더러·뱅킹 전제를 보존한 한국어 계층

## 우선 기술 목표
1. v5.1 BPS를 원본 ROM에 적용해 기준 ROM 생성
2. 원본과 기준 ROM의 해시와 바이너리 차이 기록
3. 영어 패치 또는 관련 기준 파일 확보 여부 확인
4. 실제 Huffman 트리 벡터, 스크립트 조회표, 사전, 압축 스크립트 뱅크 탐색
5. `SFGDecoder`와 일치하는 Python 디코더 구현
6. 인트로 문장 `And so began Mishaela's new ambition...`을 ROM에서 정상 디코딩
7. 성공 후에만 한국어 인코더와 새 패치 생성

## 작업 규칙
- `original/` 파일은 절대 덮어쓰지 않는다.
- 생성 파일은 `build/`에 둔다.
- 분석 결과는 `analysis/`에 기록한다.
- 스크립트와 도구는 `tools/`, `src/`, `script/`에 둔다.
- 변경 전후 SHA-256을 기록한다.
- 해결되지 않은 문제를 해결됐다고 보고하지 않는다.
- 실제 에뮬레이터 검증과 정적 분석을 구분한다.
