# Phase 6 Acceptance and Rollout Gate

Date: 2026-04-13

## Phase 6 scope

Phase 6 focuses on enterprise platform expansion:

- Export and snapshot surfaces
- Historical snapshot persistence
- Multi-host collector abstraction
- Rule-based alert policy scaffold
- Operational telemetry and self-health visibility
- Consolidated acceptance and rollout controls

## Delivered in this repository

1. Historical snapshot persistence
   - Local JSONL snapshot history at `.beads/state/snapshots.jsonl`
   - Bounded retention via `MANTICORE_SNAPSHOT_HISTORY_MAX_ENTRIES`
   - Optional age and size compaction via `MANTICORE_SNAPSHOT_HISTORY_MAX_AGE_SECS` and `MANTICORE_SNAPSHOT_HISTORY_MAX_BYTES`
   - Recent-window read path for trend context (`HIST 1H` quick tile)

2. Multi-host abstraction groundwork
   - Host-oriented collection pipeline in `SentinelEngine`
   - `SystemSnapshot.host_id` now part of core model
   - Connector ingest path remains stable while allowing future remote collectors

3. Alert policy scaffold
   - Alert rule model with metric/operator/threshold/streak semantics
   - Policy load from `MANTICORE_ALERT_POLICY_JSON` or `MANTICORE_ALERT_POLICY_PATH`
   - Snapshot evaluation and active alert surfacing in dashboard

4. Operational telemetry and self-health metrics
   - In-process telemetry for collection latency, connector poll cadence, active alerts, and error counters
   - Readouts exposed in Connectors view under "Self-health telemetry"

## Validation evidence

1. Format and tests
   - Command: `cargo fmt && cargo test`
   - Result: pass (`17 passed, 0 failed`)

2. Alert policy regression checks
   - `core::policy::tests::alert_policy_matches_threshold_rule`
   - `core::policy::tests::alert_policy_honors_for_cycles_streak`
   - Result: pass

3. Snapshot history regression check
   - `core::history::tests::append_and_read_since_with_retention`
   - Result: pass

## Acceptance checklist

- [x] Historical snapshots persist locally with retention control
- [x] Engine architecture supports host collector expansion
- [x] Alert policy scaffold evaluates snapshot metrics deterministically
- [x] Runtime self-health counters are visible to operators
- [x] Core test suite passes after integration changes

## Rollout plan

1. Enable snapshot history in non-prod first
   - Keep defaults (`enabled=false`, bounded entries when enabled)
   - Observe file growth and I/O impact under representative refresh rates

2. Trial alert policy in staging
   - Start with warning-only thresholds
   - Validate metric keys and operator semantics against expected noise levels

3. Expand to production profile
   - Add policy path to managed runtime environment
   - Monitor self-health telemetry for collector latency drift and error growth

4. Advance to remote-host implementations
   - Implement additional `HostCollector` variants for remote inputs
   - Preserve current local collector behavior as baseline fallback

## Known dependencies and constraints

- Beads dependency order currently blocks automatic closure of some child tasks until upstream issue dependencies are closed.
- Export API (`40y.1`) remains tracked separately and should be closed before forcing downstream task closure.
