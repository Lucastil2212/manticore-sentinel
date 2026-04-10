#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <artifact-path>"
  exit 1
fi

ARTIFACT="$1"
if [[ ! -f "${ARTIFACT}" ]]; then
  echo "Artifact not found: ${ARTIFACT}"
  exit 1
fi

if command -v gpg >/dev/null 2>&1; then
  gpg --armor --detach-sign "${ARTIFACT}"
  echo "Signature created: ${ARTIFACT}.asc"
else
  echo "gpg not available. Install GnuPG to sign artifacts."
  exit 2
fi
