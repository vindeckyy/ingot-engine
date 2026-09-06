#!/usr/bin/env bash
# Ingot quality gates (Plan Phase 0, unit 0.1).
#   ./scripts/check.sh          — fast gates: format, lints, unit tests
#   ./scripts/check.sh --strict — also denies clippy warnings (release gate)
set -euo pipefail
cd "$(dirname "$0")/.."

STRICT=0
if [ "${1:-}" = "--strict" ]; then
    STRICT=1
fi

echo "==> cargo fmt --check"
cargo fmt --check

echo "==> cargo clippy --workspace --all-targets"
if [ "$STRICT" = 1 ]; then
    cargo clippy --workspace --all-targets -- -D warnings
else
    cargo clippy --workspace --all-targets
fi

echo "==> cargo test --workspace"
cargo test --workspace

echo "All gates passed."
