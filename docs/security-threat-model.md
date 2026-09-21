# Security Threat Model

## Scope

Manticore Sentinel as implemented on `main`:

- local desktop operator UI (egui) and optional `--headless` collectors
- unprivileged collectors reading `/proc` and `/sys`
- helper action boundary over a Unix domain socket
- append-only, Ed25519-signed JSONL audit
- optional loopback HTTP (observability API, SSE event stream)
- optional HTTP clients to PeerWeave GraphQL and EVRUS OIDC / Evrmore RPC
- optional Docker Compose lab stack with loopback host publishes

This is **not** a multi-tenant remote administration product. Publishing HTTP
ports beyond loopback is outside the supported threat model unless the operator
adds controls this repository does not provide.

## Security Objectives

- Preserve host integrity by minimizing privileged operations.
- Prevent shell-style command injection and unintended command execution.
- Maintain action accountability through signed, append-only audit records.
- Keep network listeners off untrusted interfaces by default.
- Fail closed when `token` / `evrus` secrets are missing.

## Primary Assets

- Host process control rights (kill/renice pathways)
- Telemetry integrity (CPU, memory, process, disk, network)
- SQLite store (metrics, documents, logs, embeddings)
- Audit trail (`.beads/audit/events.jsonl`) and signing key (`.beads/audit/signing.ed25519`)
- Helper socket endpoint
- Auth tokens, EVRUS JWTs, PeerWeave CapTokens, Evrmore RPC passwords

## Trust Boundaries

1. **UI / CLI to parser and policy** — untrusted operator input → allowlist parser + RBAC gate.
2. **Core to helper** — request serialization over a local Unix socket (`0600`).
3. **Helper to kernel** — signal and priority syscalls.
4. **Runtime to audit and SQLite** — local filesystem.
5. **Observability HTTP / SSE** — loopback by default; Bearer required in `token` and `evrus` modes except `GET /health`.
6. **Connectors** — outbound HTTP only. PeerWeave and EVRUS are untrusted peers; protocol contract only.
7. **Compose network** — containers on the user-defined network can reach in-container `0.0.0.0` binds even when the host mapping is loopback.

## Threats and Mitigations

### Input and command injection

- Threat: shell metacharacters or arbitrary command payloads.
- Mitigations: allowlisted parser; shell operators rejected; bounded length; PID/nice validation.

### Privilege abuse

- Threat: unprivileged session attempts destructive actions.
- Mitigations: `MANTICORE_PRIVILEGED` + role permissions; capability-gated helper; PID `<= 1` refused; typed confirmation for kill; `token` mode never allows admin kill/renice.

### Socket boundary abuse

- Threat: another local process talks to the helper socket.
- Mitigations: owner-only `0600` socket; explicit action schema; healthcheck contract on subprocess helper.
- Residual: no client credentials on the socket (same-UID local processes can connect).

### HTTP exposure

- Threat: search, metrics, logs, or SSE leak off-host.
- Mitigations: default bind `127.0.0.1`; Compose host publishes `127.0.0.1:port`; CORS wildcard removed; `token`/`evrus` Bearer on APIs; empty secrets fail closed; non-loopback bind emits a config warning.

### Secret leakage via git

- Threat: tokens in tracked profiles or `.env`.
- Mitigations: `.gitignore` for `.env`, sqlite, keys; committed profiles have no placeholder secrets; `*.local.env` overlay for workstations.

### Replay and flooding

- Threat: high-frequency destructive requests.
- Mitigations: kill cooldown in execution policy.

### Audit tampering

- Threat: accountability loss.
- Mitigations: append-only JSONL; Ed25519 signatures on events; optional Evrmore anchoring when RPC is configured.
- Residual: an attacker with write access to the audit directory and the signing key can mint events. Protect that directory.

### Connector impersonation

- Threat: fake GraphQL/OIDC peer.
- Mitigations: operator-configured URLs; CapToken / JWT when set.
- Residual: lab stubs have no TLS and the GraphQL stub is open if the token is empty. Do not publish stub ports off loopback.

## Remaining risks

- Helper socket clients are not mutually authenticated (same-user local).
- Helper runs as the same user unless externally elevated.
- No remote attestation of binary integrity in the default workflow.
- `GET /health` is unauthenticated (intentional for Docker healthchecks).
- Compose `pid: host` expands process visibility to the host PID namespace.
- Hashed n-gram vectors are a local search aid, not a confidentiality control.

## Pre-release security checklist

Use [security-checklist.md](security-checklist.md). Minimum:

- Parser rejects shell operators and malformed tokens
- Policy denies privileged actions in unprivileged mode
- HTTP default bind is loopback; Compose publishes loopback
- No secrets in tracked files (`git grep` / review)
- `cargo test` and `./scripts/vuln-scan.sh` (when `cargo-audit` is available)

## Incident response quick actions

1. Disable privileged mode (`MANTICORE_PRIVILEGED=0`) and stop the process.
2. If HTTP was bound beyond loopback, stop Compose/the process and rotate tokens/JWTs/RPC passwords.
3. Archive `.beads/audit/` (including `signing.ed25519`) and the SQLite store before cleanup.
4. Rotate the helper socket (restart) and verify `0600` permissions.
5. Report product defects privately per [SECURITY.md](../SECURITY.md).
