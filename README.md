# agy-patch

`agy`(Antigravity CLI — **Linux & macOS**, **x86_64 & ARM64/Apple Silicon**) 바이너리의 스트리밍 출력 방식과 마크다운 렌더링 결함을 동적 심볼/시그니처 탐색으로 패치하는 초고속 모듈형 도구(Rust)입니다.

릴리즈마다 바뀌는 고정 주소에 의존하지 않고, `mmap` 제로카피 매핑으로 **ELF64**(Linux) 및 **Mach-O 64**(macOS)의 텍스트 섹션과 Go `.gopclntab` 심볼 테이블을 파싱하여 대상 함수를 찾고, 아키텍처별(`x86_64` / `ARM64`) 기계어 시그니처를 검증한 뒤 패치합니다(외부 크레이트 의존성 0, Linux `FICLONE` reflink 및 macOS `codesign -f -s -` 자동 서명 지원).

## 지원하는 패치 목록 (`--list`)

| 패치 ID | 대상 심볼 | 설명 |
| :--- | :--- | :--- |
| `nodrip` | `store.cutAtRuneBoundary` | 16ms마다 12바이트씩 끊어 찍는 타자기 딜레이(`textDrip`)를 제거하고 수신 즉시 반영 |
| `batch` | `render.renderPlannerBody` | 응답 생성 중(`Status == 1, 2, 8, 11`)에는 본문 출력을 보류하고, 완료(`DONE`) 시 완성된 마크다운 전체를 한 번에 출력 |
| `heading` | `render.glamourStyleForScheme` | 마크다운 헤딩(`H2`~`H6`) 앞에 붙는 `## `~`###### ` 프리픽스를 숨기고 색상·볼드만 유지 |
| `cjk-bold` | `goldmark/parser.ScanDelimiter` | `` **"문구"**라는 ``, `` **용어(`code`)**는 ``처럼 닫는 `**` 앞 구두점과 뒤 한글 조사가 결합될 때 볼드가 풀리는 현상 수정 |
| `tilde-strike` | `goldmark/extension.(*strikethroughParser).Parse` | `1.5.0~1.5.6`, `H2~H6` 같은 범위 표기용 단일 물결표(`~`)에 취소선이 그어지는 현상 방지 (`~~` 2개만 취소선으로 인식) |

## 빌드 및 설치

외부 의존성이 없으므로 Rust 툴체인만 있으면 인터넷 연결 없이도 1초 내에 빌드됩니다.

```bash
git clone <저장소-URL>
cd agy-patch
cargo build --release
ln -sf "$(pwd)/target/release/agy-patch" ~/.local/bin/agy-patch
```

또는 `cargo install --path .`로 설치할 수 있습니다.

## 사용법

### 1. 대화형(Interactive) 모드

터미널에서 인자 없이 실행하면 화살표/스페이스바/숫자키로 원하는 패치만 골라 체크하고, 생성할 실행 파일 이름까지 직접 입력할 수 있습니다.

```bash
agy-patch
```

### 2. CLI 옵션 모드

원하는 패치 조합(`-p`)과 최종 실행 파일 이름(`-o`)을 직접 지정할 수 있습니다. 생성된 바이너리는 자동으로 `~/.local/bin/<이름>`에 심볼릭 링크됩니다.

```bash
# 사용 가능한 패치 ID 및 설명 확인
agy-patch --list

# 모든 패치를 적용해 agy-batch 생성
agy-patch -p all -o agy-batch

# 일괄 출력(batch)만 빼고 나머지 패치를 적용해 agy-nodrip 생성
agy-patch -p nodrip,heading,cjk-bold,tilde-strike -o agy-nodrip

# 마크다운 패치 3종만 적용해 agy-md 생성
agy-patch -p heading,cjk-bold,tilde-strike -o agy-md

# 기본 프리셋 2종(agy-batch, agy-nodrip) 한 번에 갱신
agy-patch --preset

# 원본 바이너리 경로를 직접 지정할 때
agy-patch --bin /path/to/antigravity -p all -o agy-batch

# 원본을 antigravity.orig로 백업하고 기본 agy 바이너리에 직접 덮어쓰기 / 복구
agy-patch -p all --in-place
agy-patch --restore
```

## 새로운 패치 추가하기

`src/main.rs`의 `PATCH_REGISTRY` 배열에 `PatchSpec` 항목을 추가하면 대화형 UI와 `--list`, `-p` 옵션에 자동으로 반영됩니다.

## 면책 조항 및 라이선스 (Disclaimer & License)

- 본 저장소는 어떠한 독점 바이너리나 소스 코드도 포함·재배포하지 않는 비공식 로컬 패치 도구입니다.
- 로컬 바이너리 수정에 따른 모든 책임은 사용자 본인에게 있으며, 공식 고객 지원 대상에서 제외될 수 있습니다.
- 코드 자체는 [MIT License](./LICENSE)로 배포됩니다.
