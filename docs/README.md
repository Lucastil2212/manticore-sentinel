# Documentation index

Operator-facing documentation for Manticore Sentinel. Start with the root [README](../README.md) and [SECURITY.md](../SECURITY.md).

## Start here

| Document | When to read it |
|----------|-----------------|
| [configuration.md](configuration.md) | Environment variables and bind/auth defaults |
| [runtime-profiles.md](runtime-profiles.md) | `--profile` files and secret overlays |
| [docker-compose.md](docker-compose.md) | Lab Compose stack, loopback publishes |
| [auth-rbac-model.md](auth-rbac-model.md) | `local` / `token` / `evrus` and roles |
| [security-threat-model.md](security-threat-model.md) | Assets, trust boundaries, residual risk |
| [security-checklist.md](security-checklist.md) | Pre-release control verification |
| [production-runbook.md](production-runbook.md) | Deploy, health, rollback |
| [backup-recovery.md](backup-recovery.md) | Audit, SQLite, and state archives |

## Product and ecosystem

| Document | Topic |
|----------|--------|
| [manticore-ecosystem-integration.md](manticore-ecosystem-integration.md) | Protocol-only PeerWeave / EVRUS / Exchange contract |
| [collector.md](collector.md) | `/proc` and `/sys` collectors |
| [startup-diagnostics.md](startup-diagnostics.md) | Boot logging |
| [error-taxonomy.md](error-taxonomy.md) | Log categories |
| [performance-baseline.md](performance-baseline.md) | Collection timing baseline |

## Release and provenance

| Document | Topic |
|----------|--------|
| [release-readiness.md](release-readiness.md) | Release checklist |
| [pre-v1-gate.md](pre-v1-gate.md) / [pre-ga-certification-gate.md](pre-ga-certification-gate.md) | Certification gates |
| [certification-evidence.md](certification-evidence.md) | Evidence mapping |
| [sbom.md](sbom.md) | Software bill of materials |
| [artifact-signing.md](artifact-signing.md) | Release signatures |
| [provenance.md](provenance.md) | Build provenance |
| [vulnerability-scanning.md](vulnerability-scanning.md) | `cargo-audit` |
| [packaging-appimage.md](packaging-appimage.md) / [packaging-flatpak.md](packaging-flatpak.md) | Packaging scaffolds |

## Historical / design notes

[scaffold.md](scaffold.md), [truth.md](truth.md), [review-and-execution.md](review-and-execution.md), [ux-security-direction.md](ux-security-direction.md), [phase6-acceptance.md](phase6-acceptance.md), [phase7-acceptance.md](phase7-acceptance.md).
