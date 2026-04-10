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

## Examples

- Development profile:
  - `cargo run -- --profile dev`
- Secure profile:
  - `cargo run -- --profile secure`

## Notes

- Explicit environment variables in your shell can still override behavior if set after profile loading.
- Profile files are plain key-value env declarations with `#` comments supported.
