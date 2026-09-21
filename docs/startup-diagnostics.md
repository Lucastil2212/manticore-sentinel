# Startup Diagnostics

Manticore Sentinel validates runtime configuration at startup and emits structured diagnostics.

## Validated Settings

- `MANTICORE_PROFILE` (string, defaults to `default`)
- `MANTICORE_PRIVILEGED` (boolean-like: `true/false/1/0/yes/no/on/off`)
- `MANTICORE_HELPER_MODE` (`embedded` or `subprocess`)
- `MANTICORE_REFRESH_MS` (integer range `100..=5000`, defaults to `500`)
- `MANTICORE_OBS_HTTP_BIND` (default `127.0.0.1`; non-loopback emits a warning)
- `MANTICORE_AUTH_MODE` / `MANTICORE_AUTH_TOKEN` (token mode fails closed without a secret)

## Failure Behavior

- Invalid values return startup errors before launching the main UI.
- Errors are categorized under `config` taxonomy in logs.

## Visibility

- CLI logs include a startup diagnostics record with profile, privilege, helper mode, refresh interval, and observability bind.
- UI top bar shows current diagnostics summary.
