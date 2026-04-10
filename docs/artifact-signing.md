# Artifact Signing Scaffold

Sign a release artifact with GPG:

`./scripts/sign-artifact.sh <artifact-path>`

This creates:

- `<artifact-path>.asc`

## Verification

`gpg --verify <artifact-path>.asc <artifact-path>`

## Notes

- Use release-specific signing keys managed by your release process.
- Publish both artifact and detached signature together.
