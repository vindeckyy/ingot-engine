#!/usr/bin/env bash
# ==============================================================================
# Ingot Release Packaging & SBOM Generator (Plan 5.8)
# Creates:
#   - target/release/ingotd and target/release/ingot
#   - release/ingot-<version>-linux-amd64.tar.gz
#   - release/SHA256SUMS
#   - release/sbom.spdx.json
# ==============================================================================
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION=$(grep -m1 '^version' Cargo.toml | awk '{print $3}' | tr -d '"')
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
RELEASE_DIR="target/dist/v${VERSION}"
mkdir -p "$RELEASE_DIR"

echo "==> Packaging Ingot Release v${VERSION} (commit: ${COMMIT})"

echo "==> 1. Building release binaries..."
cargo build --release -p ingotd -p ingot-cli

STAGE_DIR="$(mktemp -d /tmp/ingot-dist-XXXXXX)"
cleanup() {
    rm -rf "$STAGE_DIR"
}
trap cleanup EXIT

INSTALL_DIR="$STAGE_DIR/ingot-v${VERSION}-linux-amd64"
mkdir -p "$INSTALL_DIR/bin" "$INSTALL_DIR/share/man"

cp "target/release/ingotd" "$INSTALL_DIR/bin/"
cp "target/release/ingot"  "$INSTALL_DIR/bin/"
cp "scripts/install.sh"    "$INSTALL_DIR/install.sh"
cp "scripts/ingotd.service" "$INSTALL_DIR/ingotd.service"
cp "LICENSE"               "$INSTALL_DIR/"
cp "README.md"             "$INSTALL_DIR/"
cp "docs/DOCKER_MATRIX.md" "$INSTALL_DIR/"

# Generate shell completions
mkdir -p "$INSTALL_DIR/share/completions"
"$INSTALL_DIR/bin/ingot" completions bash > "$INSTALL_DIR/share/completions/ingot.bash" 2>/dev/null || true
"$INSTALL_DIR/bin/ingot" completions zsh  > "$INSTALL_DIR/share/completions/_ingot" 2>/dev/null || true
"$INSTALL_DIR/bin/ingot" completions fish > "$INSTALL_DIR/share/completions/ingot.fish" 2>/dev/null || true

echo "==> 2. Creating release tarball..."
TARBALL="$RELEASE_DIR/ingot-v${VERSION}-linux-amd64.tar.gz"
tar -czf "$TARBALL" -C "$STAGE_DIR" "ingot-v${VERSION}-linux-amd64"

echo "==> 3. Generating SHA256SUMS..."
(cd "$RELEASE_DIR" && sha256sum "ingot-v${VERSION}-linux-amd64.tar.gz" > SHA256SUMS)

echo "==> 4. Generating Software Bill of Materials (SBOM)..."
RELEASE_DIR="$RELEASE_DIR" python3 - << 'PYEOF'
import json, os

lock_path = "Cargo.lock"
packages = []
if os.path.exists(lock_path):
    with open(lock_path) as f:
        current_pkg = {}
        for line in f:
            line = line.strip()
            if line == "[[package]]":
                if current_pkg.get("name"):
                    packages.append(current_pkg)
                current_pkg = {}
            elif line.startswith("name = "):
                current_pkg["name"] = line.split("=", 1)[1].strip().strip('"')
            elif line.startswith("version = "):
                current_pkg["version"] = line.split("=", 1)[1].strip().strip('"')
            elif line.startswith("source = "):
                current_pkg["source"] = line.split("=", 1)[1].strip().strip('"')
        if current_pkg.get("name"):
            packages.append(current_pkg)

sbom = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "Ingot-Container-Engine",
    "documentNamespace": "https://github.com/vindeckyy/ingot-engine/sbom",
    "packages": [
        {
            "name": p["name"],
            "SPDXID": f"SPDXRef-Package-{p['name']}-{p.get('version', '0')}",
            "versionInfo": p.get("version", "unknown"),
            "downloadLocation": p.get("source", "NOASSERTION")
        }
        for p in packages
    ]
}

dist_dir = os.environ.get("RELEASE_DIR", "target/dist")
with open(f"{dist_dir}/sbom.spdx.json", "w") as out:
    json.dump(sbom, out, indent=2)
print(f"SBOM written with {len(packages)} dependencies.")
PYEOF

echo
echo "==> Release packaging complete:"
ls -la "$RELEASE_DIR"
