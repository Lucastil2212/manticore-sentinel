#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/dist/provenance"
mkdir -p "${OUT_DIR}"

COMMIT_SHA="$(git -C "${ROOT_DIR}" rev-parse HEAD)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cat > "${OUT_DIR}/provenance.json" <<EOF
{
  "subject": "manticore-sentinel",
  "commit": "${COMMIT_SHA}",
  "generated_at_utc": "${TIMESTAMP}",
  "builder": "local-or-ci",
  "build_commands": [
    "cargo check",
    "cargo test",
    "cargo run -- --benchmark"
  ],
  "note": "Scaffold provenance statement; replace with signed attestations in production."
}
EOF

echo "Provenance scaffold written to ${OUT_DIR}/provenance.json"
