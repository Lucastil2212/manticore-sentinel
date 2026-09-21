# Manticore Sentinel

Desktop operator console for live system telemetry and capability-gated actions. Built for [Manticore Technology](https://manticore.technology) security operations: clear defaults for new users, progressive disclosure for advanced operators, and an audit trail for sensitive actions.

## For users

### What you get

- **Live snapshot**: CPU, memory, disk and network throughput, and top processes.
- **Command palette**: Approved commands only (no shell injection). Destructive actions require confirmation and policy checks.
- **Security posture**: Trust mode (privileged vs unprivileged helper), role-based permissions, optional token auth, and append-only audit events.
- **In-app help**: **Help Center** and **Security Guide** windows plus hover tooltips on major controls.

### Requirements

- **Rust** toolchain (see [Developers](#developers) for versions).
- **Linux** recommended for full functionality (helper uses Unix domain sockets and process signals).

### Run the application

From the repository root:

```bash
cargo run --release
```

Optional: load a predefined environment profile (see `config/profiles/`):

```bash
cargo run --release -- --profile dev
```

```bash
cargo run --release -- --profile secure
```

Profiles set variables such as `MANTICORE_PRIVILEGED`, `MANTICORE_HELPER_MODE`, and auth settings. Edit the `.env` files before production use—especially tokens.

### Command palette (quick reference)

| Command | Purpose |
|--------|---------|
| `show cpu` | Read-only acknowledgment (audited). |
| `renice <nice> <pid>` | Adjust process nice value via helper (requires permission + privileged helper when applicable). |
| `kill <pid>` | Request termination via helper; requires typed confirmation and policy permission. |

Shell metacharacters (`|`, `;`, `&`, `>`, `<`) are rejected.

### Important environment variables

| Variable | Meaning |
|----------|---------|
| `MANTICORE_PROFILE` | Logical profile name (default `default`). |
| `MANTICORE_PRIVILEGED` | When true, helper may expose kill/renice capabilities. |
| `MANTICORE_HELPER_MODE` | `embedded` or `subprocess` helper execution. |
| `MANTICORE_REFRESH_MS` | Snapshot refresh interval in ms (100–5000). |
| `MANTICORE_AUTH_MODE` | `local` or `token`. |
| `MANTICORE_ROLE` | `viewer`, `operator`, or `admin`. |
| `MANTICORE_AUTH_TOKEN` | Required in token mode (minimum length enforced). |
| `MANTICORE_AUTH_TOKEN_ISSUED_AT` | Unix seconds (token mode). |
| `MANTICORE_AUTH_TOKEN_TTL_SECS` | Token lifetime (token mode). |
| `MANTICORE_AUTH_TOKEN_GRACE_SECS` | Optional grace window (token mode). |

Full auth and RBAC semantics are documented in `docs/auth-rbac-model.md`.

### Advanced controls in the UI

Expand **Advanced Controls** (collapsed by default) to see helper socket path, audit log path, auth failure counters, lockout state, and raw runtime diagnostic string. Prefer the main view for day-to-day monitoring.

### Logging

Structured logging uses `tracing`. For example:

```bash
RUST_LOG=debug cargo run --release
```

### Other modes (CLI)

| Flag | Purpose |
|------|---------|
| `--helper-daemon` | Internal: helper subprocess entry (set by the app, not typical for end users). |
| `--benchmark` | Headless collection benchmark; prints timings to stdout. |

---

## Realtime search and ecosystem stack

Sentinel now includes an optional Compose stack for local FTS/hybrid discovery, vector indexing, PeerWeave, and EVRUS infrastructure. Services are isolated behind Compose profiles so they can be started independently and fail independently.

```bash
# Fast local full-text search

docker compose --profile search up -d --build

# Hybrid FTS + vector retrieval

docker compose --profile search --profile vector up -d --build

# Full optional ecosystem (sibling repos expected beside this checkout)
PEERWEAVE_DIR=../peer-weave EVRUS_DIR=../evrus-v0 \\
docker compose --profile search --profile vector --profile peerweave --profile evrus up -d --build
```

See `docs/realtime-search-stack.md` for the data path, search API, performance rules, and current PeerWeave GraphQL contract.


## For developers

### Prerequisites

- **Rust** with `cargo` (edition 2021; use a current stable toolchain).
- **Linux** dev environment for running helper and integration-style tests that touch processes/sockets.

### Clone and build

```bash
git clone <repository-url>
cd manticore-sentinel
cargo build --release
```

### Test

```bash
cargo test
```

Some tests spawn short-lived processes or use temporary Unix sockets; they expect a normal Linux user session.

### Run (debug, faster iteration)

```bash
cargo run
```

### Project layout (high level)

| Path | Role |
|------|------|
| `src/main.rs` | Entry: profiles, config load, benchmark/helper modes, GUI bootstrap. |
| `src/app/dashboard.rs` | Primary egui UI: telemetry, commands, help, icons, advanced section. |
| `src/core/` | Engine, snapshot, policy, commands, config, errors. |
| `src/security/` | Audit trail, auth/RBAC gate, privileged helper (UDS). |
| `src/collectors/` | Data collectors (CPU, memory, disk, network, processes). |
| `src/models/` | Metric structs shared by collectors and UI. |
| `assets/icons/` | Custom SVG icons embedded at compile time for the operator UI. |
| `config/profiles/` | Example `*.env` profiles for local vs secure-style runs. |
| `docs/` | Deeper operational and security documentation. |

### Configuration loading

`core::config::load_runtime_config()` reads environment variables and validates ranges (e.g. refresh interval, token mode requirements). The GUI dashboard uses the same loader for consistency with CLI startup logging.

### UI assets (SVG)

Icons are included with `include_bytes!` from `assets/icons/`. `egui_extras` registers image loaders once when visuals initialize. New icons should be small, single-purpose SVGs; keep stroke/fill colors aligned with the existing tactical palette if you extend the set.

### Issue tracking (Beads)

This repository may use **Beads** (`.beads/`) for in-repo issues. Typical workflow:

```bash
bd list
bd show <issue-id>
bd create "Title"
bd update <issue-id> --claim
```

### Documentation index

- `docs/auth-rbac-model.md` — Authentication modes, roles, permissions, token lifecycle, lockout, audit behavior.
- Other `docs/*.md` files — Packaging, runbooks, certification gates, etc., as present in your checkout.

### Security notes for contributors

- Do not bypass the command parser for operator input.
- Keep destructive actions on the helper boundary; avoid `Command::shell` or stringly shell execution.
- Preserve append-only audit semantics for security-relevant outcomes.
- When changing auth or policy, update `docs/auth-rbac-model.md` and add or adjust tests in `src/security/`.

---

## License and branding

Manticore Sentinel is part of the Manticore Technology product line. Use and distribution terms follow the license file in this repository if one is present; otherwise clarify with the repository owner.
