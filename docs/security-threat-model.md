# Security Threat Model

## Scope

This document defines the security posture for Manticore Sentinel as currently implemented:

- local desktop operator UI
- unprivileged collectors reading `/proc` and `/sys`
- helper action boundary over Unix domain socket
- append-only audit log

## Security Objectives

- Preserve host integrity by minimizing privileged operations.
- Prevent shell-style command injection and unintended command execution.
- Maintain action accountability through immutable audit records.
- Enforce explicit trust-state communication to operators.

## Primary Assets

- Host process control rights (kill/renice pathways).
- Telemetry integrity for CPU, memory, process, disk, and network views.
- Audit trail correctness (`.beads/audit/events.jsonl`).
- Helper socket endpoint confidentiality/integrity.

## Trust Boundaries

1. **UI to Core Parser/Policy**
   - Boundary: untrusted operator input -> token parser + policy gate.
2. **Core to Helper**
   - Boundary: request serialization over local Unix socket.
3. **Helper to Kernel**
   - Boundary: syscall execution for signal and priority operations.
4. **Runtime to Audit Storage**
   - Boundary: append-only event write path to local filesystem.

## Threats and Mitigations

## Input and Command Injection

- Threat: shell metacharacters or arbitrary command payloads.
- Mitigations:
  - strict token parser with explicit command allowlist
  - shell operators explicitly rejected
  - bounded command length and PID/nice validation

## Privilege Abuse

- Threat: unprivileged session attempts destructive actions.
- Mitigations:
  - privileged mode requirement via execution policy
  - capability-gated helper actions (`KillProcess`, `ReniceProcess`)
  - protected PID refusal (`<= 1`)
  - destructive action typed confirmation in UI

## Socket Boundary Abuse

- Threat: unauthorized local access to helper socket.
- Mitigations:
  - socket path created with owner-only permissions (`0600`)
  - startup contract via healthcheck
  - explicit action schema with strict fields

## Replay and Flooding Risk

- Threat: repeated high-frequency destructive requests.
- Mitigations:
  - kill cooldown policy window
  - centralized execution policy checks before helper dispatch

## Audit Tampering Risk

- Threat: action accountability loss due to missing or mutable logs.
- Mitigations:
  - append-only JSONL write pattern
  - event capture from helper boundary and read-only commands
  - periodic visibility in dashboard audit panel

## Remaining Risks

- No cryptographic signature on audit events yet.
- No peer credential verification on socket clients yet.
- Helper currently runs as same user unless externally elevated.
- No remote attestation of binary integrity in current local workflow.

## Pre-Release Security Checklist

- [ ] Parser rejects shell operators and malformed tokens.
- [ ] Policy denies privileged actions in unprivileged mode.
- [ ] Kill action requires typed confirmation.
- [ ] Helper refuses protected PIDs.
- [ ] Helper socket permissions are owner-only.
- [ ] Helper healthcheck handshake succeeds in subprocess mode.
- [ ] Audit events are written for each action pathway.
- [ ] Unit tests and integration tests pass (`cargo test`).
- [ ] Benchmark mode runs without error (`cargo run -- --benchmark`).
- [ ] Dependency review completed (`cargo tree` + advisory scan if available).

## Incident Response Quick Actions

- Disable privileged mode (`MANTICORE_PRIVILEGED=0`).
- Switch helper mode to embedded for local containment.
- Archive `.beads/audit/events.jsonl` before any cleanup.
- Re-run test and benchmark commands to verify runtime behavior.
