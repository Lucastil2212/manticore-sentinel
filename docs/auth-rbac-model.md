# Auth and RBAC Model

This document defines the runtime authorization model for operator actions.

## Authentication Modes

- `local`: Local operator session boundary, intended for single-host operation.
- `token`: Token-authenticated boundary for remote/API usage.

## Roles

- `viewer`: Read-only telemetry visibility.
- `operator`: Read + process renice permission.
- `admin`: Full local control, including kill and renice.

## Permissions

- `ViewSystemMetrics`: Observe local snapshot and dashboard metrics.
- `ReniceProcess`: Adjust process nice values through the helper boundary.
- `KillProcess`: Send process termination requests through the helper boundary.

## Boundary Rules

- All destructive actions flow through the helper socket boundary.
- Policy evaluation gates command execution before helper calls.
- In `token` mode, `admin` is treated as non-destructive for safety (kill/renice denied).
- Every accepted or denied helper action is append-only audited in JSONL.
- Authentication denials (missing, invalid, or expired token) are also appended to audit events.
- Repeated auth failures trigger temporary lockout backoff (starting at 10s, capped at 60s).
- The operator command UI shows auth readiness, failure count, and active lockout countdown.
- In-app Help Center and hover tooltips provide command, navigation, and safety guidance without external docs.

## Runtime Configuration

- `MANTICORE_AUTH_MODE=local|token`
- `MANTICORE_ROLE=viewer|operator|admin`
- `MANTICORE_AUTH_TOKEN=<secret>` required when auth mode is `token` (minimum 12 chars)
- `MANTICORE_AUTH_TOKEN_ISSUED_AT=<unix-seconds>` required in token mode
- `MANTICORE_AUTH_TOKEN_TTL_SECS=<seconds>` required in token mode (60..=604800)
- `MANTICORE_AUTH_TOKEN_GRACE_SECS=<seconds>` optional in token mode (default `30`, max `600`)
- `MANTICORE_PRIVILEGED=true|false` controls helper capabilities startup posture.

