# Configuration

Runtime configuration is environment-only. `--profile <name>` loads
`config/profiles/<name>.env`, then an optional gitignored
`config/profiles/<name>.local.env` (local file wins). Variables already set in
the process environment are not overwritten by the committed profile.

Never put real tokens in tracked profile files. See
[config/profiles/README.md](../config/profiles/README.md).

## Authentication and role

| Variable | Default | Notes |
|----------|---------|--------|
| `MANTICORE_PROFILE` | `default` | Logical name in logs |
| `MANTICORE_AUTH_MODE` | `local` | `local` \| `token` \| `evrus` |
| `MANTICORE_ROLE` | `viewer` if unprivileged, else `admin` | `viewer` \| `operator` \| `admin` |
| `MANTICORE_AUTH_TOKEN` | unset | Required in `token` mode, minimum 12 characters. **Do not commit.** |
| `MANTICORE_AUTH_TOKEN_ISSUED_AT` | required in token mode | Unix seconds |
| `MANTICORE_AUTH_TOKEN_TTL_SECS` | required in token mode | 60–604800 |
| `MANTICORE_AUTH_TOKEN_GRACE_SECS` | `30` | 0–600 |
| `MANTICORE_PRIVILEGED` | `false` | Enables helper kill/renice capabilities |
| `MANTICORE_HELPER_MODE` | `embedded` | `embedded` \| `subprocess` |

`token` mode never grants destructive admin actions. Details:
[auth-rbac-model.md](auth-rbac-model.md).

## Collectors

| Variable | Default | Notes |
|----------|---------|--------|
| `MANTICORE_REFRESH_MS` | `1000` | Clamped 100–5000 |
| `MANTICORE_PROCESS_MAX_ENTRIES` | implementation default | Top process table cap |
| `MANTICORE_PROCESS_CMDLINE_ENTRIES` | implementation default | Cmdline capture cap |

## Storage and search

| Variable | Default | Notes |
|----------|---------|--------|
| `MANTICORE_STORE_ENABLED` | `true` | SQLite WAL |
| `MANTICORE_STORE_PATH` | `.beads/state/sentinel.sqlite` | Restrict directory permissions |
| `MANTICORE_SEARCH_ENABLED` | `true` | FTS5 + hashed n-gram vectors |

## Observability HTTP and SSE

| Variable | Default | Notes |
|----------|---------|--------|
| `MANTICORE_OBS_HTTP_ENABLED` | `false` (`true` with `--headless`) | Enables the HTTP API |
| `MANTICORE_OBS_HTTP_PORT` | `9463` | |
| `MANTICORE_OBS_HTTP_BIND` | `127.0.0.1` | Non-loopback binds emit a config warning. Docker images set `0.0.0.0` *inside the container* and publish the host port to `127.0.0.1` |
| `MANTICORE_EVENT_STREAM_ENABLED` | `false` | SSE on loopback |
| `MANTICORE_EVENT_STREAM_PORT` | `9462` | Always `127.0.0.1` |
| `MANTICORE_LOG_JSON` | `false` | Structured `tracing` JSON |

In `token` or `evrus` mode, every observability route except `GET /health`
requires `Authorization: Bearer <secret>`. Empty secrets fail closed. There is
no `Access-Control-Allow-Origin: *` header.

`--healthcheck` always probes `http://127.0.0.1:<port>/health`.

## PeerWeave (optional, HTTP GraphQL)

| Variable | Default | Notes |
|----------|---------|--------|
| `MANTICORE_PEERWEAVE_ENABLED` | `false` | |
| `MANTICORE_PEERWEAVE_GRAPHQL_URL` | `http://localhost:3200/graphql` | Prefer `127.0.0.1` |
| `MANTICORE_PEERWEAVE_CAP_TOKEN` | unset | **Do not commit.** |
| `MANTICORE_PEERWEAVE_POLL_MS` | `5000` | 1000–30000 |
| `MANTICORE_PEERWEAVE_PUBLISH_ENABLED` | `false` | |
| `MANTICORE_PEERWEAVE_PUBLISH_SPACE_ID` | unset | Required to publish |
| `MANTICORE_PEERWEAVE_PUBLISH_MS` | `5000` | 1000–30000 |

## EVRUS (optional, OIDC + JSON-RPC)

| Variable | Default | Notes |
|----------|---------|--------|
| `MANTICORE_EVRUS_ENABLED` | `false` | |
| `MANTICORE_EVRUS_OIDC_URL` | `http://localhost:8790` | Prefer `127.0.0.1` |
| `MANTICORE_EVRUS_JWT` | unset | Required for `evrus` HTTP auth. **Do not commit.** |
| `MANTICORE_EVRUS_ANCHOR_ENABLED` | `false` | Evrmore audit anchoring |
| `MANTICORE_EVRUS_ANCHOR_INTERVAL_SECS` | `300` | 30–86400 |
| `MANTICORE_EVRUS_RPC_URL` | unset | |
| `MANTICORE_EVRUS_RPC_USER` / `MANTICORE_EVRUS_RPC_PASS` | unset | **Do not commit.** |

## Audit and snapshot history

| Variable | Default | Notes |
|----------|---------|--------|
| `MANTICORE_AUDIT_MAX_ENTRIES` | `10000` | 500–500000 |
| `MANTICORE_AUDIT_ARCHIVE_ENABLED` | `true` | |
| `MANTICORE_SNAPSHOT_HISTORY_ENABLED` | `false` | JSONL under `.beads/state` |
| `MANTICORE_SNAPSHOT_HISTORY_MAX_ENTRIES` | `1000` | |
| `MANTICORE_SNAPSHOT_HISTORY_MAX_AGE_SECS` | unset | `0`/empty disables |
| `MANTICORE_SNAPSHOT_HISTORY_MAX_BYTES` | unset | `0`/empty disables |
| `MANTICORE_SNAPSHOT_HISTORY_SLIM_RECORDS` | `false` | |
| `MANTICORE_SNAPSHOT_HISTORY_RESET_ON_START` | `false` | Destructive; lab only |
| `MANTICORE_ALERT_POLICY_JSON` / `MANTICORE_ALERT_POLICY_PATH` | unset | Optional alert scaffold |
