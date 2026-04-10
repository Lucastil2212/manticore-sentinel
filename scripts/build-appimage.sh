#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APPDIR="${ROOT_DIR}/dist/AppDir"
BIN_NAME="manticore-sentinel"

rm -rf "${APPDIR}"
mkdir -p "${APPDIR}/usr/bin" "${APPDIR}/usr/share/applications" "${APPDIR}/usr/share/icons/hicolor/256x256/apps"

pushd "${ROOT_DIR}" >/dev/null
cargo build --release
popd >/dev/null

cp "${ROOT_DIR}/target/release/${BIN_NAME}" "${APPDIR}/usr/bin/${BIN_NAME}"

cat > "${APPDIR}/${BIN_NAME}.desktop" <<EOF
[Desktop Entry]
Name=Manticore Sentinel
Exec=${BIN_NAME}
Icon=${BIN_NAME}
Type=Application
Categories=System;Monitor;
EOF

cat > "${APPDIR}/AppRun" <<'EOF'
#!/usr/bin/env bash
HERE="$(dirname "$(readlink -f "$0")")"
exec "${HERE}/usr/bin/manticore-sentinel" "$@"
EOF
chmod +x "${APPDIR}/AppRun"

touch "${APPDIR}/usr/share/icons/hicolor/256x256/apps/${BIN_NAME}.png"

echo "AppDir prepared at: ${APPDIR}"
echo "Next: use linuxdeploy and appimagetool to generate final AppImage."
