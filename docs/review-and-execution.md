# Manticore Sentinel - In-Depth Review and Execution Baseline

## What the Current Docs Establish Well

- `docs/truth.md` correctly defines the product as a zero-trust, kernel-proximate Linux observability platform with strict separation between UI, core, and privileged helper.
- `docs/scaffold.md` and `docs/collector.md` outline a practical Rust module layout and initial collector approach that match the architecture in `docs/truth.md`.
- The stack choices are coherent: Rust + `procfs` + `tokio` for MVP, with future direct syscalls and eBPF expansion.
- Security direction is clear: no shell execution, explicit capability model, minimal privileged surface, and auditable actions.

## Gaps and Risks to Address Early

1. **Inconsistency between docs and executable baseline**
   - `docs/scaffold.md` contains at least one import typo (`cate::models::memory::MemoryMetrics`) and placeholders (`Vec<()>`) that need immediate replacement with typed models.
2. **Privilege boundary not yet concretely specified**
   - `docs/truth.md` defines helper constraints but does not yet define transport schema versioning, authn/authz strategy on UDS, or replay protection.
3. **UX security posture is thematic, not yet operational**
   - The docs mention zero trust, but UI-level threat signaling, intent confirmation, and audit traceability need concrete interaction patterns.
4. **No explicit acceptance tests per phase**
   - Phase plan is strong, but testable "done criteria" are not yet attached to each milestone.
5. **No unified delivery backlog**
   - The technical plan exists, but there was no dependency-aware execution graph before this setup.

## Execution Decisions Locked In

- Build order:
  1. Working Rust scaffold (compiles, runs, snapshots)
  2. Collector hardening (CPU, memory, process, disk, network)
  3. UI shell (read-only)
  4. Command palette with strict parser
  5. Privileged helper MVP (kill, renice) with capability checks
  6. Audit, sandboxing, and performance budgets
- Product constraints:
  - No shell-based metrics or shell command interpretation in command system
  - Unprivileged-by-default runtime
  - Every privileged action requires auditable intent
- Tooling:
  - `beads` is the source of truth for execution and dependency tracking

## Beads Workflow for This Project

- `bd ready` is the default queue for next actions.
- Use `bd show <id>` before implementing a task.
- Use `bd update <id> --claim` when starting and `bd close <id> "reason"` when done.
- All design and implementation work is mapped to epics/tasks with explicit dependencies.

## Definition of Done (Program-Level)

- MVP dashboard provides stable 250-500ms snapshots for CPU, memory, process, disk, and network.
- Command system supports only enumerated actions with token parser and no shell semantics.
- Privileged helper has minimal syscall wrappers and capability checks with audit trail.
- Security UX provides operator visibility into action intent, risk level, and action provenance.
- Runtime overhead stays within target envelope (<2% CPU, <50MB memory under normal local load).
