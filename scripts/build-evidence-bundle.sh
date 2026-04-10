#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/dist/evidence"
STAMP="$(date +%Y%m%d-%H%M%S)"
BUNDLE="${OUT_DIR}/manticore-evidence-${STAMP}.tar.gz"

mkdir -p "${OUT_DIR}"

INCLUDE=(
  "dist/sbom"
  "dist/security"
  "dist/provenance"
  "docs/security-checklist.md"
  "docs/security-threat-model.md"
  "docs/pre-v1-gate.md"
  "docs/release-readiness.md"
)

pushd "${ROOT_DIR}" >/dev/null
EXISTING=()
for item in "${INCLUDE[@]}"; do
  if [[ -e "${item}" ]]; then
    EXISTING+=("${item}")
  fi
done
if [[ ${#EXISTING[@]} -eq 0 ]]; then
  echo "No evidence inputs found."
  exit 1
fi
tar -czf "${BUNDLE}" "${EXISTING[@]}"
popd >/dev/null

echo "Evidence bundle created: ${BUNDLE}"
