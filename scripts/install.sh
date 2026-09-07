#!/usr/bin/env bash
# Install Ingot from source.
#   ./scripts/install.sh            — release build, install to /usr/local
#   ./scripts/install.sh --prefix=/opt/ingot
#   ./scripts/install.sh --debug    — debug build
set -euo pipefail

PREFIX="/usr/local"
DEBUG=0

for arg in "$@"; do
    case "$arg" in
        --prefix=*) PREFIX="${arg#--prefix=}" ;;
        --debug)    DEBUG=1 ;;
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

echo "==> Building ingotd and ingot ($PROFILE)"
cargo build $BUILD_FLAGS -p ingotd -p ingot-cli

echo "==> Installing to $PREFIX/bin"
install -d "$PREFIX/bin"
install -m 0755 "target/$PROFILE/ingotd" "$PREFIX/bin/ingotd"
install -m 0755 "target/$PROFILE/ingot"  "$PREFIX/bin/ingot"

echo "==> Installing systemd unit"
install -d /etc/systemd/system 2>/dev/null || true
if [ -d /etc/systemd/system ]; then
    install -m 0644 scripts/ingotd.service /etc/systemd/system/ingotd.service
    echo "    Installed. Enable with: sudo systemctl enable --now ingotd"
fi

echo "==> Installing shell completions"
install -d "$PREFIX/share/bash-completion/completions" 2>/dev/null || true
install -d "$PREFIX/share/zsh/site-functions"          2>/dev/null || true
install -d "$PREFIX/share/fish/completions"            2>/dev/null || true
if [ -d "$PREFIX/share/bash-completion/completions" ]; then
    ingot completions bash > "$PREFIX/share/bash-completion/completions/ingot" 2>/dev/null || true
fi
if [ -d "$PREFIX/share/zsh/site-functions" ]; then
    ingot completions zsh > "$PREFIX/share/zsh/site-functions/_ingot" 2>/dev/null || true
fi
if [ -d "$PREFIX/share/fish/completions" ]; then
    ingot completions fish > "$PREFIX/share/fish/completions/ingot.fish" 2>/dev/null || true
fi

echo
echo "Ingot installed:"
echo "  Daemon:  $PREFIX/bin/ingotd"
echo "  CLI:     $PREFIX/bin/ingot"
echo
echo "Start the daemon:"
echo "  sudo ingotd"
echo
echo "Use the Docker CLI against it:"
echo "  export DOCKER_HOST=unix:///run/ingot/ingot.sock"
echo "  docker version"
