# S25U에서 할 일 — 쉬운 순서

## 이번에 한 번만

1. S25U에서 **Termux**를 엽니다.
2. 아래 명령을 위에서부터 한 줄씩 실행합니다.

~~~sh
cd ~/storage/shared/ShiningForceKR
bash tools/manage_s25u_autopilot.sh stop
git pull --ff-only
bash tools/manage_s25u_autopilot.sh install --interval 60
~~~

3. 마지막에 `S25U autopilot started`가 나오면 완료입니다.

원본 ROM은 기존 위치
`내부 저장공간/ROM/Shining Force Gaiden - Final Conflict (Japan).gg`에
그대로 둡니다. ROM 파일을 올리거나 옮기지 않습니다.

## 이후에는

자동실행기가 60초마다 새 작업을 확인합니다. 기준 ROM과 시험 ROM을
같은 지점에서 각각 실행하고 화면 픽셀을 비교합니다.

- 화면이 한 픽셀도 바뀌지 않은 후보: 자동 탈락 후 다음 후보 실행
- 화면이 바뀐 후보: 자동으로 멈추고 사람 확인 대기
- 한 번의 작업에서 자동 탈락 후보를 최대 8개까지 연속 처리

진행 확인:

1. **내 파일** 앱을 엽니다.
2. `내부 저장공간 > ShiningForceKR > reports`로 이동합니다.
3. `AUTOPILOT_STATUS.txt`에서 `상태: 실행 중`인지 확인합니다.
4. `NEXT_STEP.txt`를 열고 적힌 안내만 따르면 됩니다.

## 사진을 보내야 할 때

자동 상태가 사람 확인을 요구할 때만 다음 파일을 올립니다.

1. `evidence > local > v5_1_test_phrase > 최신 폴더 > baseline`에서
   `frame_0090.png`
2. 같은 최신 폴더의 `test`에서 `frame_0090.png`
3. 같은 `test` 폴더에서 `after_advance.png`

글자가 입력되는 중간 상태도 확인해야 한다고 안내받은 경우에만
`frame_0001.png`, `frame_0008.png`, `frame_0030.png`도 함께 올립니다.

## 오류가 보일 때

ROM이나 생성 ROM을 올리지 말고 다음 두 파일의 **글자 내용만** 보냅니다.

- `reports/AUTOPILOT_STATUS.txt`
- `reports/NEXT_STEP.txt`

Termux에서 직접 확인하려면 다음 명령을 실행합니다.

~~~sh
cd ~/storage/shared/ShiningForceKR
bash tools/manage_s25u_autopilot.sh status
bash tools/manage_s25u_autopilot.sh logs
~~~
