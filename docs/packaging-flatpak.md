# Flatpak Packaging Scaffold

Flatpak manifest:

- `packaging/flatpak/io.manticore.Sentinel.yml`

## Local build example

From repository root:

- `flatpak-builder --force-clean build-dir packaging/flatpak/io.manticore.Sentinel.yml`

## Local run example

- `flatpak-builder --run build-dir packaging/flatpak/io.manticore.Sentinel.yml manticore-sentinel`

## Notes

- The current manifest is a scaffold and may require runtime permission tuning.
- Review `finish-args` before distribution and keep them minimal.
