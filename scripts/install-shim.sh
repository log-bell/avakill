#!/bin/sh
# Install avakill-shim binary from GitHub Releases.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/log-bell/avakill/main/scripts/install-shim.sh | sh
#
# Or with a specific version:
#   curl -fsSL ... | sh -s -- v0.4.0

set -e

REPO="log-bell/avakill"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="avakill-shim"

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Darwin) echo "darwin" ;;
        Linux)  echo "linux" ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *) echo "unsupported"; return 1 ;;
    esac
}

# Detect architecture
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  echo "amd64" ;;
        arm64|aarch64) echo "arm64" ;;
        *) echo "unsupported"; return 1 ;;
    esac
}

# Get latest release tag
get_latest_version() {
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' \
        | head -1 \
        | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/'
}

main() {
    OS=$(detect_os)
    ARCH=$(detect_arch)

    if [ "$OS" = "unsupported" ] || [ "$ARCH" = "unsupported" ]; then
        echo "Error: unsupported platform $(uname -s)/$(uname -m)" >&2
        exit 1
    fi

    # Version from argument or latest
    VERSION="${1:-}"
    if [ -z "$VERSION" ]; then
        echo "Fetching latest release..."
        VERSION=$(get_latest_version)
        if [ -z "$VERSION" ]; then
            echo "Error: could not determine latest version" >&2
            exit 1
        fi
    fi

    EXT=""
    if [ "$OS" = "windows" ]; then
        EXT=".exe"
    fi

    FILENAME="${BINARY_NAME}-${OS}-${ARCH}${EXT}"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${FILENAME}"

    echo "Downloading ${FILENAME} (${VERSION})..."
    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT

    HTTP_CODE=$(curl -fsSL -w "%{http_code}" -o "${TMPDIR}/${FILENAME}" "$URL")
    if [ "$HTTP_CODE" != "200" ]; then
        echo "Error: download failed (HTTP $HTTP_CODE)" >&2
        echo "URL: $URL" >&2
        exit 1
    fi

    chmod +x "${TMPDIR}/${FILENAME}"

    # Install
    TARGET="${INSTALL_DIR}/${BINARY_NAME}"
    if [ -w "$INSTALL_DIR" ]; then
        mv "${TMPDIR}/${FILENAME}" "$TARGET"
    else
        echo "Installing to ${TARGET} (requires sudo)..."
        sudo mv "${TMPDIR}/${FILENAME}" "$TARGET"
    fi

    echo "Installed ${BINARY_NAME} ${VERSION} to ${TARGET}"
    "${TARGET}" --version
}

main "$@"
