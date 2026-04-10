#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/dist/sbom"
mkdir -p "${OUT_DIR}"

if command -v cargo-cyclonedx >/dev/null 2>&1; then
  pushd "${ROOT_DIR}" >/dev/null
  cargo cyclonedx --format json --output-file "${OUT_DIR}/cyclonedx.json"
  popd >/dev/null
  echo "SBOM generated at ${OUT_DIR}/cyclonedx.json"
else
  cat > "${OUT_DIR}/README.txt" <<'EOF'
cargo-cyclonedx not found.
Install with:
  cargo install cargo-cyclonedx
Then run:
  ./scripts/generate-sbom.sh
EOF
  echo "SBOM tool missing. Wrote guidance to ${OUT_DIR}/README.txt"
fi
