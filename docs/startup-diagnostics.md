# Startup Diagnostics

Manticore Sentinel validates runtime configuration at startup and emits structured diagnostics.

## Validated Settings

- `MANTICORE_PROFILE` (string, defaults to `default`)
- `MANTICORE_PRIVILEGED` (boolean-like: `true/false/1/0/yes/no/on/off`)
- `MANTICORE_HELPER_MODE` (`embedded` or `subprocess`)
- `MANTICORE_REFRESH_MS` (integer range `100..=5000`, defaults to `500`)

## Failure Behavior

- Invalid values return startup errors before launching the main UI.
- Errors are categorized under `config` taxonomy in logs.

## Visibility

- CLI logs include a startup diagnostics record with profile, privilege, helper mode, and refresh interval.
- UI top bar shows current diagnostics summary.
