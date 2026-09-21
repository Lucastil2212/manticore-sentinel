# Runtime profiles

Profiles are example environment files loaded with `--profile <name>`. They are
checked into git so a clone can start quickly. They must never contain real
secrets.

| File | Intended use |
|------|----------------|
| `dev.env` | Unprivileged desktop development (`local` / `viewer`). |
| `stack.env` | Lab Compose / mixed local connectors. Loopback HTTP, unprivileged. |
| `secure.env` | Privileged helper + `token` auth. Supply `MANTICORE_AUTH_TOKEN` in the environment. |
| `secure.local.env` (gitignored) | Optional overlay for a workstation token. |
| `ecosystem.env` | EVRUS + PeerWeave connectors. Supply JWT, CapToken, and RPC credentials in the environment. |

## Overlaying secrets

Create `config/profiles/<name>.local.env` (gitignored) or export variables in
your shell *after* the profile loads. Profile files do not override variables
that are already set in the process environment.

```bash
export MANTICORE_AUTH_TOKEN="$(openssl rand -hex 16)"
export MANTICORE_AUTH_TOKEN_ISSUED_AT="$(date +%s)"
cargo run --release -- --profile secure
```

See [docs/runtime-profiles.md](../../docs/runtime-profiles.md) and
[docs/configuration.md](../../docs/configuration.md).
