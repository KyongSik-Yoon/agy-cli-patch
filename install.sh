#!/bin/sh
set -eu

REPO="KyongSik-Yoon/agy-cli-patch"
BIN_NAME="agy-cli-patch"
INSTALL_DIR="${AGY_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${AGY_CLI_PATCH_VERSION:-latest}"
MODE="release"
LINK_LOCAL=0

usage() {
    cat <<EOF
agy-cli-patch 설치 스크립트

사용법:
  curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | sh
  ./install.sh [옵션]

옵션:
  --version <tag>   설치할 릴리즈 태그 지정 (예: v0.2.0, 기본: latest)
  --dir <path>      설치 디렉토리 지정 (기본: ~/.local/bin)
  --build           릴리즈 다운로드 대신 현재 저장소에서 cargo build --release 후 설치
  --link            (--build와 함께 사용) 복사 대신 target/release 바이너리로 심볼릭 링크 생성
  -h, --help        도움말 출력
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version)
            [ "$#" -ge 2 ] || { echo "오류: --version 값이 필요합니다." >&2; exit 1; }
            VERSION="$2"
            shift 2
            ;;
        --dir)
            [ "$#" -ge 2 ] || { echo "오류: --dir 값이 필요합니다." >&2; exit 1; }
            INSTALL_DIR="$2"
            shift 2
            ;;
        --build)
            MODE="build"
            shift
            ;;
        --link)
            LINK_LOCAL=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "오류: 알 수 없는 옵션 '$1'" >&2
            usage >&2
            exit 1
            ;;
    esac
done

mkdir -p "$INSTALL_DIR"

if [ "$MODE" = "build" ]; then
    command -v cargo >/dev/null 2>&1 || { echo "오류: cargo를 찾을 수 없습니다." >&2; exit 1; }
    cargo build --release
    SRC_BIN="$(pwd)/target/release/$BIN_NAME"
    [ -f "$SRC_BIN" ] || { echo "오류: 빌드 결과물을 찾을 수 없습니다: $SRC_BIN" >&2; exit 1; }
    if [ "$LINK_LOCAL" -eq 1 ]; then
        ln -sf "$SRC_BIN" "$INSTALL_DIR/$BIN_NAME"
        echo "심볼릭 링크 생성 완료: $INSTALL_DIR/$BIN_NAME -> $SRC_BIN"
    else
        cp "$SRC_BIN" "$INSTALL_DIR/$BIN_NAME"
        chmod 755 "$INSTALL_DIR/$BIN_NAME"
        echo "설치 완료: $INSTALL_DIR/$BIN_NAME"
    fi
    exit 0
fi

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)  ASSET_OS="linux" ;;
    Darwin) ASSET_OS="macos" ;;
    *)
        echo "오류: 지원하지 않는 OS입니다: $OS" >&2
        exit 1
        ;;
esac

case "$ARCH" in
    x86_64|amd64)  ASSET_ARCH="x86_64" ;;
    aarch64|arm64) ASSET_ARCH="aarch64" ;;
    *)
        echo "오류: 지원하지 않는 아키텍처입니다: $ARCH" >&2
        exit 1
        ;;
esac

ARCHIVE="${BIN_NAME}-${ASSET_OS}-${ASSET_ARCH}.tar.gz"

if [ "$VERSION" = "latest" ]; then
    BASE_URL="https://github.com/$REPO/releases/latest/download"
else
    BASE_URL="https://github.com/$REPO/releases/download/$VERSION"
fi

download() {
    url="$1"
    out="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$out"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$out" "$url"
    else
        echo "오류: curl 또는 wget이 필요합니다." >&2
        exit 1
    fi
}

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

echo "다운로드 중: $BASE_URL/$ARCHIVE"
if ! download "$BASE_URL/$ARCHIVE" "$TMP_DIR/$ARCHIVE"; then
    echo "오류: 릴리즈 아카이브를 내려받지 못했습니다 ($BASE_URL/$ARCHIVE)." >&2
    echo "힌트: 릴리즈가 아직 없다면 저장소에서 './install.sh --build'로 직접 빌드해 설치하세요." >&2
    exit 1
fi

if download "$BASE_URL/SHA256SUMS.txt" "$TMP_DIR/SHA256SUMS.txt" 2>/dev/null; then
    EXPECTED="$(grep "  $ARCHIVE\$" "$TMP_DIR/SHA256SUMS.txt" | awk '{print $1}' || true)"
    if [ -n "$EXPECTED" ]; then
        if command -v sha256sum >/dev/null 2>&1; then
            ACTUAL="$(sha256sum "$TMP_DIR/$ARCHIVE" | awk '{print $1}')"
        elif command -v shasum >/dev/null 2>&1; then
            ACTUAL="$(shasum -a 256 "$TMP_DIR/$ARCHIVE" | awk '{print $1}')"
        else
            ACTUAL=""
        fi
        if [ -n "$ACTUAL" ] && [ "$EXPECTED" != "$ACTUAL" ]; then
            echo "오류: SHA-256 체크섬이 일치하지 않습니다." >&2
            exit 1
        fi
    fi
fi

tar -xzf "$TMP_DIR/$ARCHIVE" -C "$TMP_DIR"
[ -f "$TMP_DIR/$BIN_NAME" ] || { echo "오류: 압축 해제 후 바이너리를 찾을 수 없습니다." >&2; exit 1; }

mv "$TMP_DIR/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"
chmod 755 "$INSTALL_DIR/$BIN_NAME"

echo "설치 완료: $INSTALL_DIR/$BIN_NAME"
case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
        echo "참고: $INSTALL_DIR 이 PATH에 없습니다. 셸 설정에 추가하세요:"
        echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
        ;;
esac
