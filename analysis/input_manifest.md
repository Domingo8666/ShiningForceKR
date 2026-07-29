# 입력 자료 식별표

마지막 정적 검증일: 2026-07-29

파일 자체가 아니라 식별값만 기록합니다. 원본 ROM과 외부 참조 IPS는 GitHub에 저장하지 않습니다.

| 자료 | 위치/상태 | 크기 | SHA-256 | CRC32 |
|---|---|---:|---|---|
| 깨끗한 일본판 ROM | S25U original/ 로컬 전용 | 524,288 | 4705256cc1a242aab7fea170369eb64723f796e27c6edfe0f93a674a8ba00f42 | 6019FE5E |
| 한국어 v5.1 BPS | patch/Final_Conflict_Japan_to_Korean_v5.1.bps | 1,080,753 | 7f92221afc8dc4b13712776d7eeca3571b9896fd746cefbc44b5a5806501633b | 798763CB |
| v5.1 적용 결과 | S25U build/ 로컬 전용 | 1,556,480 | 모바일 빌드 때 기록 | 23BAC434 |
| 영어 070706 ZIP | 외부 다운로드, 저장하지 않음 | 42,691 | 2e218cc5456c7e621517c4a3521c1c462aa66e663d764e3187496757cbf3bc5e | - |
| 영어 070706 IPS | S25U patch/ 로컬 전용 | 47,290 | 3cc1085508c7298d5d20fbfefec929cdfdadbcd60340a66ec0e4c2aa92d48c07 | - |

## 확인 규칙

- tools/analyze_v5_1.py 는 원본과 BPS 식별값 및 BPS 내부 CRC를 모두 확인한 뒤 적용합니다.
- tools/fetch_fc_english_patch.py 는 ZIP과 추출된 IPS의 SHA-256을 모두 확인합니다.
- 해시가 하나라도 다르면 작업을 중단합니다.
- 생성 ROM은 커밋하지 않습니다.

## 출처

- 영어 패치: https://fantasyanime.com/shiningforce/sffc_downloads.htm
- 원본 식별값 교차 확인: https://retrohackers.net/translation-details.php?id=876
