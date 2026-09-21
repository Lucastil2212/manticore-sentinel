#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-${ROOT_DIR}/backups}"
STAMP="$(date +%Y%m%d-%H%M%S)"
ARCHIVE="${OUT_DIR}/manticore-state-${STAMP}.tar.gz"

mkdir -p "${OUT_DIR}"

pushd "${ROOT_DIR}" >/dev/null
INCLUDE=(
  ".beads/config.yaml"
  ".beads/metadata.json"
  ".beads/audit"
  ".beads/state/sentinel.sqlite"
  ".beads/state/sentinel.sqlite-wal"
  ".beads/state/sentinel.sqlite-shm"
  "config/profiles"
  "docs/security-checklist.md"
  "docs/security-threat-model.md"
  "docs/performance-baseline.md"
  "SECURITY.md"
)
EXISTING=()
for item in "${INCLUDE[@]}"; do
  if [[ -e "${item}" ]]; then
    EXISTING+=("${item}")
  fi
done
if [[ ${#EXISTING[@]} -eq 0 ]]; then
  echo "No backup inputs found."
  exit 1
fi
# Keep gitignored secret overlays out of the archive.
tar -czf "${ARCHIVE}" \
  --exclude='config/profiles/*.local.env' \
  "${EXISTING[@]}"
popd >/dev/null

echo "Backup created: ${ARCHIVE}"
