# Runtime Profiles

Start with:

```bash
cargo run --release -- --profile <name>
```

That loads `config/profiles/<name>.env`. Variables **already set in the
environment are left unchanged**. If `config/profiles/<name>.local.env` exists
(gitignored), it is applied next and may set secrets.

Tracked profile files are examples. They must not contain tokens, JWTs, or
passwords. See [config/profiles/README.md](../config/profiles/README.md).

## Available profiles

### `dev`

- `MANTICORE_PRIVILEGED=false`
- `MANTICORE_HELPER_MODE=embedded`
- `MANTICORE_AUTH_MODE=local`, `MANTICORE_ROLE=viewer`

### `stack`

Lab / Compose companion. Unprivileged, local auth, observability on
**loopback**. Connector URLs point at `127.0.0.1`. Not a production posture.

### `secure`

- `MANTICORE_PRIVILEGED=true`
- `MANTICORE_HELPER_MODE=subprocess`
- `MANTICORE_AUTH_MODE=token`

You must export a unique token **before** start or the process exits:

```bash
export MANTICORE_AUTH_TOKEN="$(openssl rand -hex 16)"
export MANTICORE_AUTH_TOKEN_ISSUED_AT="$(date +%s)"
cargo run --release -- --profile secure
```

### `ecosystem`

- `MANTICORE_AUTH_MODE=evrus`
- PeerWeave + EVRUS connectors enabled
- Publish path scaffolded (disabled by default)
- Evrmore anchoring enabled (RPC credentials **not** in the file — set them in the environment)
- Snapshot history enabled under `.beads/state`

## Examples

```bash
cargo run --release -- --profile dev
cargo run --release -- --profile stack
```

## Notes

- Profile files are `KEY=value` with `#` comments.
- Do not copy production secrets into `config/profiles/*.env`.
- Snapshot history stays off unless a profile or env var enables it.
