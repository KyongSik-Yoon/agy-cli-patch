# agy-cli-patch

`agy`(Antigravity CLI — **Linux & macOS**, **x86_64 & ARM64/Apple Silicon**) 바이너리의 스트리밍 출력 방식과 마크다운 렌더링 결함을 동적 심볼/시그니처 탐색으로 패치하는 초고속 모듈형 도구(Rust)입니다.

릴리즈마다 바뀌는 고정 주소에 의존하지 않고, `mmap` 제로카피 매핑으로 **ELF64**(Linux) 및 **Mach-O 64**(macOS)의 텍스트 섹션과 Go `.gopclntab` 심볼 테이블을 파싱하여 대상 함수를 찾고, 아키텍처별(`x86_64` / `ARM64`) 기계어 시그니처를 검증한 뒤 패치합니다(외부 크레이트 의존성 0, Linux `FICLONE` reflink 및 macOS `codesign -f -s -` 자동 서명 지원). 단, `banner`·`release-notes` 패치는 현재 `x86_64`에서만 지원합니다.

## 지원하는 패치 목록 (`--list`)

| 패치 ID | 대상 심볼 | 설명 |
| :--- | :--- | :--- |
| `nodrip` | `store.cutAtRuneBoundary` | 16ms마다 12바이트씩 끊어 찍는 타자기 딜레이(`textDrip`)를 제거하고 수신 즉시 반영 |
| `batch` | `render.renderPlannerBody` | 응답 생성 중(`Status == 1, 2, 8, 11`)에는 본문 출력을 보류하고, 완료(`DONE`) 시 완성된 마크다운 전체를 한 번에 출력 |
| `heading` | `render.glamourStyleForScheme` | 마크다운 헤딩(`H2`~`H6`) 앞에 붙는 `## `~`###### ` 프리픽스를 숨기고 색상·볼드만 유지 |
| `cjk-bold` | `goldmark/parser.ScanDelimiter` | `` **"문구"**라는 ``, `` **용어(`code`)**는 ``처럼 닫는 `**` 앞 구두점과 뒤 한글 조사가 결합될 때 볼드가 풀리는 현상 수정 |
| `tilde-strike` | `goldmark/extension.(*strikethroughParser).Parse` | `1.5.0~1.5.6`, `H2~H6` 같은 범위 표기용 단일 물결표(`~`)에 취소선이 그어지는 현상 방지 (`~~` 2개만 취소선으로 인식) |
| `banner` | `render.BannerWithInfo` | 상단 `Antigravity CLI 1.5.7` 옆에 `(patch v0.2.0)` 형태로 패치 버전 표시 (`x86_64`) |
| `release-notes` | `render.BuildHeader` | 로고 아래에 패치 기능 요약 및 GitHub 저장소 정보 표시 (`x86_64`, **기본 꺼짐** — `-p all,release-notes`처럼 명시해야 적용) |

## 빌드 및 설치

외부 의존성이 없으므로 Rust 툴체인만 있으면 인터넷 연결 없이도 빠르게 빌드됩니다.

```bash
git clone https://github.com/KyongSik-Yoon/agy-cli-patch.git
cd agy-cli-patch
cargo build --release
ln -sf "$(pwd)/target/release/agy-cli-patch" ~/.local/bin/agy-cli-patch
```

또는 `cargo install --path .`로 설치할 수 있습니다.

## 사용법

### 1. 대화형(Interactive) 모드

터미널에서 인자 없이 실행하면 `패치 선택 → 출력 방식 → 확인` 3단계 화면이 열립니다.

```bash
agy-cli-patch
```

- **패치 선택**: `↑↓`(또는 `j`/`k`)로 이동, `space`나 숫자키로 선택, `a`로 전체 선택/해제. 커서가 가리키는 패치의 설명과 대상 심볼이 하단에 표시됩니다. 실행 전에 각 패치를 대상 바이너리에 미리 대조하므로, 적용할 수 없는 패치(예: ARM64의 `banner`)는 `✕`와 사유가 표시되고 선택되지 않습니다. `batch`를 켜면 `nodrip`도 함께 켜집니다.
- **출력 방식**: 새 실행 파일(이름을 바로 편집, 생성 경로와 `~/.local/bin` 링크를 미리 보여줌) 또는 기본 agy에 직접 덮어쓰기(in-place) 중에서 고릅니다. 원본과 같은 경로나 존재하지 않는 디렉토리는 막고, 기존 링크가 다른 파일을 가리키면 교체된다고 경고합니다.
- **확인**: 적용할 패치와 출력 경로를 확인한 뒤 `enter`로 실행합니다. `esc`로 이전 단계, `q`나 `ctrl+c`로 종료합니다(터미널 상태는 항상 복구됩니다).

외부 크레이트 없이 ANSI 이스케이프로 그리며, `NO_COLOR` 환경변수를 설정하면 색 없이 표시됩니다.

### 2. CLI 옵션 모드

원하는 패치 조합(`-p`)과 최종 실행 파일 이름(`-o`)을 직접 지정할 수 있습니다. 생성된 바이너리는 자동으로 `~/.local/bin/<이름>`에 심볼릭 링크됩니다.

```bash
# 사용 가능한 패치 ID 및 설명 확인
agy-cli-patch --list

# 기본 활성 패치 전체를 적용해 agy-batch 생성 ('all'은 기본 꺼짐 패치를 포함하지 않음)
agy-cli-patch -p all -o agy-batch

# 릴리즈 노트 배너까지 포함
agy-cli-patch -p all,release-notes -o agy-batch

# 릴리즈 노트를 터미널에서 확인 (바이너리는 건드리지 않음)
agy-cli-patch --notes

# 일괄 출력(batch)만 빼고 나머지 패치를 적용해 agy-nodrip 생성
agy-cli-patch -p nodrip,heading,cjk-bold,tilde-strike,banner -o agy-nodrip

# 마크다운 패치 3종만 적용해 agy-md 생성
agy-cli-patch -p heading,cjk-bold,tilde-strike -o agy-md

# 기본 프리셋 2종(agy-batch, agy-nodrip) 한 번에 갱신
agy-cli-patch --preset

# 원본 바이너리 경로를 직접 지정할 때
agy-cli-patch --bin /path/to/antigravity -p all -o agy-batch

# 원본을 antigravity.orig로 백업하고 기본 agy 바이너리에 직접 덮어쓰기 / 복구
agy-cli-patch -p all --in-place
agy-cli-patch --restore
```

## 주의 사항

### agy 자체 업데이트

agy는 실행할 때마다 백그라운드로 새 버전을 확인하고, 있으면 **설치된 위치의 `antigravity` 바이너리를 직접 교체**합니다. 그 결과:

- `--in-place`로 적용한 패치가 업데이트와 함께 사라집니다. 다시 `agy-cli-patch -p all --in-place`를 실행하면 됩니다(패치가 풀린 것을 감지하면 `antigravity.orig` 백업도 새 버전으로 갱신).
- mise로 설치한 경우 디렉토리명과 실제 버전이 어긋납니다(예: `~/.local/share/mise/installs/agy/1.5.6/antigravity`가 실제로는 1.5.7). 패처는 경로와 함께 실제 버전을 출력하므로 `[*] 대상 바이너리: … (버전 1.5.7)` 줄로 확인할 수 있습니다.

버전 관리를 mise 등 패키지 매니저에만 맡기려면 자체 업데이트를 끕니다. 값은 반드시 `true`여야 합니다(`1`은 적용되지 않음).

```bash
export AGY_CLI_DISABLE_AUTO_UPDATE=true
```

mise를 쓴다면 `~/.config/mise/config.toml`에 넣을 수 있습니다.

```toml
[env]
AGY_CLI_DISABLE_AUTO_UPDATE = "true"
```

### `-o`와 심볼릭 링크

`-o`에 경로(`/tmp/agy-test` 등)를 주더라도 `~/.local/bin/<파일 이름>` 심볼릭 링크가 함께 생성되며, 같은 이름의 기존 링크는 덮어씌워집니다(다른 파일을 가리키던 링크라면 `[!]` 경고를 출력). 테스트용 바이너리를 만들 때는 기존 명령과 겹치지 않는 이름을 쓰세요.

원본을 망가뜨리는 출력은 대화형 모드와 `-o` 모두에서 거부합니다.

- 결과물 경로가 대상 바이너리, 패치 원본, `antigravity.orig` 백업과 같은 경우 (원본에 적용하려면 `--in-place`)
- `~/.local/bin/<파일 이름>` 자리에 원본 바이너리가 있어 링크로 바뀌게 되는 경우
- `~/.local/bin/<파일 이름>` 자리에 링크가 아닌 일반 파일·디렉토리가 있는 경우 (원래 쓰던 다른 프로그램을 지우지 않도록. `--preset`도 동일)
- 결과물이 곧 `~/.local/bin/<파일 이름>`인 경우(agy가 `~/.local/bin`에 설치된 경우)에는 링크를 따로 만들지 않습니다.

### remote-control 데몬

`agy-batch remote-control serve` 등으로 데몬을 띄워 두었다면, 해당 바이너리를 다시 생성하기 전에 데몬을 멈추고 생성 후 재시작하세요. agy를 재설치해 데몬이 `not signed in`으로 종료되면 `agy-batch remote-control start`로 다시 등록합니다.

## 새로운 패치 추가하기

`src/main.rs`의 `PATCH_REGISTRY` 배열에 `PatchSpec` 항목을 추가하면 대화형 UI와 `--list`, `-p` 옵션에 자동으로 반영됩니다.

## 면책 조항 및 라이선스 (Disclaimer & License)

- 본 저장소는 어떠한 독점 바이너리나 소스 코드도 포함·재배포하지 않는 비공식 로컬 패치 도구입니다.
- 로컬 바이너리 수정에 따른 모든 책임은 사용자 본인에게 있으며, 공식 고객 지원 대상에서 제외될 수 있습니다.
- 코드 자체는 [MIT License](./LICENSE)로 배포됩니다.
