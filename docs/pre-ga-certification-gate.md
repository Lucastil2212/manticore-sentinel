# Pre-GA Security Certification Gate

Complete this before `v1.0.0` GA release:

## Mandatory Artifacts

- [ ] SBOM generated (`dist/sbom/`)
- [ ] Vulnerability scan report generated (`dist/security/`)
- [ ] Provenance statement generated (`dist/provenance/provenance.json`)
- [ ] Artifact signature created and verification tested
- [ ] Evidence bundle archive generated (`dist/evidence/`)

## Validation Commands

```bash
cargo check
cargo test
cargo run -- --benchmark
./scripts/generate-sbom.sh
./scripts/vuln-scan.sh
./scripts/generate-provenance.sh
./scripts/build-evidence-bundle.sh
```

## Security Review Signoff

- Security lead:
- Release engineering:
- Product owner:
- GA decision date:
