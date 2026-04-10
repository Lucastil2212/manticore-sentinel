# Error Taxonomy

Manticore Sentinel categorizes runtime issues into these classes:

- `collector` - metric sampling, parsing, or snapshot failures
- `helper` - helper startup, IPC, or privileged action handling failures
- `policy` - action denied by execution policy controls
- `config` - invalid or missing profile/configuration values
- `runtime` - uncategorized application/runtime failures

## Logging Conventions

- Structured logs are emitted with:
  - `category`
  - `message`
  - context fields (e.g., `profile`, `pid`, `action`) where available
- Default log level is `info`.
- Set `RUST_LOG` to override, for example:
  - `RUST_LOG=debug cargo run -- --profile dev`

## Operational Use

- Treat `helper` and `policy` categories as security-sensitive.
- Treat recurring `collector` errors as data quality or compatibility issues.
- Include category counts in release candidate reviews.
