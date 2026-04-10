#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/dist/security"
mkdir -p "${OUT_DIR}"

if command -v cargo-audit >/dev/null 2>&1; then
  pushd "${ROOT_DIR}" >/dev/null
  cargo audit --json > "${OUT_DIR}/cargo-audit.json"
  popd >/dev/null
  echo "Vulnerability scan report at ${OUT_DIR}/cargo-audit.json"
else
  cat > "${OUT_DIR}/audit-readme.txt" <<'EOF'
cargo-audit not found.
Install with:
  cargo install cargo-audit
Then run:
  ./scripts/vuln-scan.sh
EOF
  echo "Vulnerability scanner missing. Wrote guidance to ${OUT_DIR}/audit-readme.txt"
fi
