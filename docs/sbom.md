# SBOM Generation

Generate software bill of materials artifacts:

`./scripts/generate-sbom.sh`

## Output

- `dist/sbom/cyclonedx.json` (when `cargo-cyclonedx` is installed)

## Tooling

Install generator:

`cargo install cargo-cyclonedx`

## Usage in release flow

- Run SBOM generation for every release candidate.
- Archive SBOM in certification evidence bundle.
