# Runtime Profiles

Manticore Sentinel supports profile-based startup via:

`cargo run -- --profile <name>`

Profiles are loaded from `config/profiles/<name>.env`.

## Available Profiles

- `dev`
  - `MANTICORE_PRIVILEGED=false`
  - `MANTICORE_HELPER_MODE=embedded`
- `secure`
  - `MANTICORE_PRIVILEGED=true`
  - `MANTICORE_HELPER_MODE=subprocess`
- `ecosystem`
  - `MANTICORE_AUTH_MODE=evrus`
  - PeerWeave + EVRUS connectors enabled
  - Optional PeerWeave graph publish path is scaffolded (disabled by default)
  - Evrmore audit anchoring enabled (RPC credentials required)
  - Local snapshot history persistence enabled (`.beads/state/snapshots.jsonl`)

## Examples

- Development profile:
  - `cargo run -- --profile dev`
- Secure profile:
  - `cargo run -- --profile secure`
- Ecosystem profile:
  - `cargo run -- --profile ecosystem`

## Notes

- Explicit environment variables in your shell can still override behavior if set after profile loading.
- Profile files are plain key-value env declarations with `#` comments supported.
- `ecosystem` profile includes placeholder secrets/tokens; replace before use.
