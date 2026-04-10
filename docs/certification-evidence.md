# Certification Evidence Bundle

Create release evidence archive:

`./scripts/build-evidence-bundle.sh`

Output:

- `dist/evidence/manticore-evidence-<timestamp>.tar.gz`

## Bundle Contents (when available)

- SBOM outputs (`dist/sbom/`)
- Vulnerability scan outputs (`dist/security/`)
- Provenance statement (`dist/provenance/`)
- Security and release gate documents

## Release Usage

- Generate bundle for every release candidate.
- Attach bundle to release artifacts or internal compliance record.
