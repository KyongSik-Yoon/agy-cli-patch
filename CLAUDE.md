# agy-cli-patch

## 홈페이지

- 주소: https://kyongsik-yoon.github.io/agy-cli-patch/ (GitHub Pages, `main` 브랜치의 `docs/index.html` 한 파일. 빌드 없음)
- 컨셉: "패치 스위치 터미널" — 스위치를 켜고 끄면 같은 agy 응답이 그 자리에서 달라지는 시연. 색은 대화형 UI의 ANSI 색(시안 강조, 초록 선택)을 따른다.
- 움직이는 부분은 모두 실제 동작의 시연이다: 첫 화면 자동 시연, 패치별 전후 미리보기, 심볼→시그니처→쓰기 과정, 조작되는 대화형 화면(`Wizard::handle_key` 를 옮긴 것), 설치 출력. 장식은 첫 화면 배경의 바이트 하나뿐.
- 대화형 화면 끝의 오프셋과 `0xa4720c0` 은 agy 1.5.7(Linux x86_64)에 실제로 돌려 얻은 값이다. 새로 재지 않았다면 다른 버전 값으로 바꿔 쓰지 않는다.
- 이전 판은 `docs/classic.html` 에 보존한다.
- 숫자와 문구(16ms·12바이트, 패치 ID·심볼, 버전, 시그니처 바이트, 대화형 화면 문구)는 `README.md`와 `src/main.rs`(`PATCH_REGISTRY`, `X86_CUT_*`/`ARM64_CUT_*`, `Wizard`)에 맞춘다.
- 패치 목록·동작·버전·설치 방법이 바뀌면 홈페이지도 함께 고친다.
