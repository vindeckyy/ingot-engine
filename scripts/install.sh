#!/usr/bin/env bash
# Install Ingot from source.
#   ./scripts/install.sh                       — release build, install to /usr/local/bin
#   ./scripts/install.sh --prefix=/opt/ingot   — install to /opt/ingot/bin
#   ./scripts/install.sh --destdir=/tmp/stage  — stage files under /tmp/stage
#   ./scripts/install.sh --service             — also install systemd service (requires root)
#   ./scripts/install.sh --debug               — build and install debug binaries
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
DESTDIR="${DESTDIR:-}"
DEBUG=0
INSTALL_SERVICE=0

for arg in "$@"; do
    case "$arg" in
        --prefix=*)   PREFIX="${arg#--prefix=}" ;;
        --destdir=*)  DESTDIR="${arg#--destdir=}" ;;
        --service)    INSTALL_SERVICE=1 ;;
        --debug)      DEBUG=1 ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --prefix=DIR     Installation prefix (default: /usr/local)"
            echo "  --destdir=DIR    Staging directory prepended to install paths (default: empty)"
            echo "  --service        Install systemd service unit into /etc/systemd/system (requires root)"
            echo "  --debug          Build and install unoptimized debug binaries"
            exit 0
            ;;
        *) echo "unknown option: $arg"; exit 1 ;;
    esac
done

cd "$(dirname "$0")/.."

PROFILE="release"
BUILD_FLAGS="--release"
if [ "$DEBUG" = 1 ]; then
    PROFILE="debug"
    BUILD_FLAGS=""
fi

TARGET_INGOT="target/$PROFILE/ingot"
TARGET_INGOTD="target/$PROFILE/ingotd"

echo "==> Building ingotd and ingot ($PROFILE)"
cargo build $BUILD_FLAGS -p ingotd -p ingot-cli

BINDIR="$DESTDIR$PREFIX/bin"
echo "==> Installing binaries to $BINDIR"
install -d "$BINDIR"
install -m 0755 "$TARGET_INGOTD" "$BINDIR/ingotd"
install -m 0755 "$TARGET_INGOT"  "$BINDIR/ingot"

echo "==> Installing shell completions using built ingot binary"
BASH_COMP_DIR="$DESTDIR$PREFIX/share/bash-completion/completions"
ZSH_COMP_DIR="$DESTDIR$PREFIX/share/zsh/site-functions"
FISH_COMP_DIR="$DESTDIR$PREFIX/share/fish/completions"

install -d "$BASH_COMP_DIR" "$ZSH_COMP_DIR" "$FISH_COMP_DIR" 2>/dev/null || true
if [ -d "$BASH_COMP_DIR" ]; then
    "$TARGET_INGOT" completions bash > "$BASH_COMP_DIR/ingot" 2>/dev/null || true
fi
if [ -d "$ZSH_COMP_DIR" ]; then
    "$TARGET_INGOT" completions zsh > "$ZSH_COMP_DIR/_ingot" 2>/dev/null || true
fi
if [ -d "$FISH_COMP_DIR" ]; then
    "$TARGET_INGOT" completions fish > "$FISH_COMP_DIR/ingot.fish" 2>/dev/null || true
fi

echo "==> Installing man pages"
MAN1_DIR="$DESTDIR$PREFIX/share/man/man1"
MAN8_DIR="$DESTDIR$PREFIX/share/man/man8"
install -d "$MAN1_DIR" "$MAN8_DIR" 2>/dev/null || true
if [ -d "$MAN1_DIR" ]; then
    install -m 0644 docs/man/ingot.1 "$MAN1_DIR/ingot.1" 2>/dev/null || true
fi
if [ -d "$MAN8_DIR" ]; then
    install -m 0644 docs/man/ingotd.8 "$MAN8_DIR/ingotd.8" 2>/dev/null || true
fi

if [ "$INSTALL_SERVICE" = 1 ]; then
    SYSTEMD_DIR="$DESTDIR/etc/systemd/system"
    echo "==> Installing systemd unit to $SYSTEMD_DIR"
    install -d "$SYSTEMD_DIR"
    # Adjust ExecStart in service file to match PREFIX
    sed "s|ExecStart=/usr/local/bin/ingotd|ExecStart=$PREFIX/bin/ingotd|" scripts/ingotd.service > "$SYSTEMD_DIR/ingotd.service"
    chmod 0644 "$SYSTEMD_DIR/ingotd.service"
    echo "    Systemd unit installed. Enable with: sudo systemctl enable --now ingotd"
fi

echo
echo "Ingot installed successfully:"
echo "  Daemon:  $PREFIX/bin/ingotd"
echo "  CLI:     $PREFIX/bin/ingot"
echo
echo "To run the daemon (root required for container namespaces/cgroups/mounts):"
echo "  sudo $PREFIX/bin/ingotd"
echo
echo "To use the companion CLI or Docker CLI:"
echo "  export DOCKER_HOST=unix:///run/ingot/ingot.sock"
echo "  $PREFIX/bin/ingot doctor"
echo "  docker version"

