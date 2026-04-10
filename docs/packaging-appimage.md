# AppImage Packaging Scaffold

## Build AppDir

Run:

`./scripts/build-appimage.sh`

This script:
- builds the release binary
- prepares `dist/AppDir`
- writes desktop/AppRun launcher metadata

## Generate AppImage

After preparing AppDir, use your local AppImage tooling:

- `linuxdeploy` for bundling dependencies
- `appimagetool` for final image creation

Example flow (tool paths may vary):

- `linuxdeploy --appdir dist/AppDir --desktop-file dist/AppDir/manticore-sentinel.desktop --output appimage`

## Notes

- Replace placeholder icon at:
  - `dist/AppDir/usr/share/icons/hicolor/256x256/apps/manticore-sentinel.png`
- Keep this pipeline reproducible in CI by pinning tool versions.
