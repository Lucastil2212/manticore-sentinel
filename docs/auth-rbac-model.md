# Auth and RBAC Model

This document defines the runtime authorization model for operator actions and
optional HTTP surfaces.

## Authentication modes

- `local`: Single-host operator session. HTTP APIs (if enabled) are reachable
  by any process on the bind address with no Bearer token. Keep the bind on
  loopback.
- `token`: Shared-secret boundary for the GUI token gate, observability HTTP,
  and SSE. Requires `MANTICORE_AUTH_TOKEN` (minimum 12 characters) plus
  issued-at / TTL. Empty secrets fail closed.
- `evrus`: Operator identity from an EVRUS-issued JWT (`MANTICORE_EVRUS_JWT`).
  Observability HTTP and SSE require `Authorization: Bearer <jwt>`. JWT
  cryptographic validation against EVRUS JWKS is a connector concern; missing
  JWT fails closed on those HTTP surfaces.

## Roles

- `viewer`: Read-only telemetry.
- `operator`: Read + process renice (when privileged helper allows it).
- `admin`: Kill and renice in `local` / `evrus` modes.

## Permissions

- `ViewSystemMetrics`: Observe local snapshot and dashboard metrics.
- `ReniceProcess`: Adjust process nice values through the helper boundary.
- `KillProcess`: Send process termination requests through the helper boundary.

## Boundary rules

- All destructive actions flow through the helper socket boundary.
- Policy evaluation gates command execution before helper calls.
- In `token` mode, `admin` is treated as non-destructive (kill/renice denied).
- Every accepted or denied helper action is append-only audited (Ed25519-signed JSONL).
- Authentication denials (missing, invalid, or expired token) are appended to audit events.
- Repeated auth failures trigger temporary lockout backoff (starting at 10s, capped at 60s).
- Observability HTTP: `GET /health` is unauthenticated (Docker healthcheck). All other
  routes require Bearer when mode is `token` or `evrus`.
- SSE event stream uses the same Bearer rules and always binds `127.0.0.1`.

## Runtime configuration

- `MANTICORE_AUTH_MODE=local|token|evrus`
- `MANTICORE_ROLE=viewer|operator|admin`
- `MANTICORE_AUTH_TOKEN` required when auth mode is `token` (minimum 12 chars). **Do not commit.**
- `MANTICORE_AUTH_TOKEN_ISSUED_AT=<unix-seconds>` required in token mode
- `MANTICORE_AUTH_TOKEN_TTL_SECS=<seconds>` required in token mode (60..=604800)
- `MANTICORE_AUTH_TOKEN_GRACE_SECS=<seconds>` optional in token mode (default `30`, max `600`)
- `MANTICORE_EVRUS_JWT` required for evrus-mode HTTP surfaces
- `MANTICORE_PRIVILEGED=true|false` controls helper capabilities startup posture

See [configuration.md](configuration.md).
