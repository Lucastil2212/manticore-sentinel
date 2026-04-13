# Phase 7 Acceptance Evidence

Date: 2026-04-13

## Checks run

1. Standalone behavior and baseline performance
   - Command: `cargo run -- --benchmark`
   - Result:
     - `benchmark.startup_ms=50.347`
     - `benchmark.collect_avg_ms=47.226`
     - `benchmark.collect_hz=21.175`
     - `benchmark.iterations=40`
   - Outcome: pass

2. Connector failure degradation (no PeerWeave/EVRUS services reachable)
   - Command:
     - `MANTICORE_PEERWEAVE_ENABLED=true MANTICORE_PEERWEAVE_GRAPHQL_URL=http://127.0.0.1:9/graphql MANTICORE_EVRUS_ENABLED=true MANTICORE_EVRUS_OIDC_URL=http://127.0.0.1:9 MANTICORE_EVRUS_ANCHOR_ENABLED=true MANTICORE_EVRUS_RPC_URL=http://127.0.0.1:9 MANTICORE_EVRUS_RPC_USER=none MANTICORE_EVRUS_RPC_PASS=none cargo run -- --benchmark`
   - Result:
     - process exited successfully
     - repeated connector warnings without crash
     - `benchmark.startup_ms=48.128`
     - `benchmark.collect_avg_ms=165.679`
     - `benchmark.collect_hz=6.036`
     - `benchmark.iterations=40`
   - Outcome: pass (graceful degradation confirmed)

3. Unit/regression test suite
   - Command: `cargo test`
   - Result: `14 passed, 0 failed`
   - Outcome: pass

## Scope completed in this repo

- Multi-view dashboard: System/PeerWeave/EVRUS/Audit/Connectors
- PeerWeave and EVRUS connector views with disabled/degraded handling
- Trust badge identity source states (`LOCAL`, `EVRUS`, `ANCHORED`)
- DID actor attribution in audit events
- Ed25519 signing for audit events
- Audit Merkle root computation over canonical JSON
- Evrmore JSON-RPC anchoring flow and anchor state persistence
- EVRUS policy bridge with deterministic constraints and policy hash attribution
- Benchmark mode now includes connector polling when connectors are enabled

## Remaining live-environment validations

These checks require running PeerWeave/EVRUS/Evrmore services and were not executed in this local run:

- PeerWeave live node health rendering against a real GraphQL endpoint
- EVRUS OIDC JWT validation against live discovery/JWKS responses
- End-to-end Evrmore anchor transaction confirmation with real `txid`/`blockheight`
- Cross-repo documentation sync validation (`peer-weave` and `evrus-v0` copies)
