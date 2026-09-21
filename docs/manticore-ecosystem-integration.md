# Manticore Ecosystem Integration

## Source of Truth for Cross-Project Architecture

**Status:** Active design contract
**Updated:** September 18, 2026 — added Manticore Asset Exchange as a fourth product with an explicit non-compatibility boundary against EVRUS Trade and PeerWeave wire formats. EVRUS source of truth for that adapter is `evrus-v0`.
**Canonical location:** `manticore-sentinel/docs/manticore-ecosystem-integration.md`
**Copies:** `peer-weave/docs/manticore-ecosystem-integration.md`, `evrus-v0/docs/manticore-ecosystem-integration.md`
**Related:** `manticore-exchange/docs/ECOSYSTEM.md`
**Date:** April 12, 2026
**Author:** Lucas Tilford

When this document conflicts with a project-local design doc, resolve by updating both to match the intended behavior and noting the resolution here.

---

## 1. Ecosystem Vision

Manticore Technologies builds local-first, verifiable infrastructure. Four flagship products form the operational backbone:

- **PeerWeave** — Local-first CRDT workspaces, P2P identity/sync, semantic knowledge graph, agent-native runtime. The collaboration and intelligence substrate.
- **EVRUS Vault** (`evrus-v0`) — Sovereign identity, Evrmore wallet, policy-gated asset operations, encrypted messaging. The identity and value layer, connected to the Evrmore blockchain.
- **Manticore Asset Exchange** — Noncustodial public discovery relay and atomic swap coordination (`max.*.v1`). Hosted on Render without wallets.
- **Manticore Sentinel** — Zero-trust, kernel-proximate Linux observability console with capability-gated privileged actions and append-only audit. The operations layer.

The vision is:

> **Every Manticore node runs on PeerWeave's knowledge fabric infrastructure and connects to the Evrmore ecosystem through EVRUS.**

Sentinel is the **Manticore Ecosystem Operations Console** — the single interface where an operator monitors system health, PeerWeave node state, and EVRUS vault status, with identity backed by EVRUS and telemetry flowing through PeerWeave's knowledge graph.

---

## 2. Product Roles and Boundaries

### 2.1 PeerWeave — The Fabric

PeerWeave owns the collaboration and data substrate. It provides:

- **Spaces** — CRDT-synchronized workspaces (folder-backed, DAG-committed)
- **P2P networking** — libp2p (QUIC/TCP, Noise/TLS, Gossipsub, mDNS, rendezvous, relay)
- **Knowledge graph** — Per-space SQLite graph store, GraphQL HTTP API with CapToken auth
- **Agent runtime** — In-process module execution with traced syscalls (WASM deferred)
- **Identity** — Device-centric DID/CapToken model (Ed25519), capability enforcement
- **Ports and Mirrors** — Service exposure and publication artifacts with signed provenance

**What PeerWeave provides to the ecosystem:**
- A place to store and query structured data (graph)
- A way to sync that data across hosts (CRDT + Gossipsub)
- A capability-scoped identity model for attributing actions
- A protocol for service advertisement and invocation (Ports)

### 2.2 EVRUS Vault — The Identity and Value Layer

EVRUS owns sovereign identity and blockchain connectivity. It provides:

- **Local-first vault** — Encrypted keystore, mnemonic/SLIP39 recovery, WebAuthn step-up
- **Evrmore integration** — UTXO wallet (address-index RPCs), asset operations (issue, transfer, metadata), `.evr` naming
- **Policy engine** — Deterministic pre-signing evaluation (royalty enforcement, recipient allowlists, time windows)
- **P2P messaging** — X3DH/Double Ratchet over libp2p Gossipsub
- **OIDC bridge** — Local OpenID Connect provider issuing EdDSA JWTs, DID document endpoint
- **Capabilities** — ZCAP-LD import with Ed25519 single-proof verification

**What EVRUS provides to the ecosystem:**
- Verified operator identity (OIDC tokens with DID backing)
- Policy evaluation for gating privileged actions
- Blockchain anchoring (Evrmore transactions for audit hashes, asset metadata)
- `.evr` naming as human-readable identity aliases

### 2.3 Manticore Sentinel — The Operations Console

Sentinel owns system observability and operational control. It provides:

- **Linux telemetry** — CPU, memory, disk, network, process collectors reading `/proc` and `/sys`
- **Command palette** — Token-parsed, shell-injection-proof command system
- **Privileged helper** — Capability-gated kill/renice over Unix domain socket
- **Audit trail** — Append-only JSONL events for every privileged action
- **RBAC** — Local/token auth modes with viewer/operator/admin roles
- **Dashboard** — egui real-time operator interface with trust-state communication

**What Sentinel provides to the ecosystem:**
- Real-time host health data for any machine running Manticore infrastructure
- An auditable record of operational actions taken on those machines
- A single pane of glass showing system, PeerWeave, and EVRUS status

### 2.4 Manticore Asset Exchange — Public Discovery Relay

Manticore Asset Exchange (MAX) is the hosted, **noncustodial** public marketplace. Evrmore settles ownership; a local companion holds signing authority; a Render HTTPS relay publishes signed offers and ciphertext. It is **not** wire-compatible with EVRUS Trade (`/evrus/trade/offers/1.0.0`) or PeerWeave actor envelopes.

**What MAX provides:**
- Public `max.offer.v1` discovery (FTS5 + local LSA) and a provenance graph of maker assertions
- Dual-authenticated `max.envelope.v1` coordination (X-Wing / ML-DSA-65 + Ed25519)
- Interactive atomic settlement of one Evrmore transaction (`max.swap.v1`)
- A testnet-only Render Blueprint; wallets, vaults, and Core RPC never run on Render

**Identity boundary:** MAX fingerprints are `mx1_` hashes of the MAX key bundle. They are not `did:key`, libp2p PeerIds, or `.evr` names. Do not import EVRUS or PeerWeave keys into a MAX vault.

**Adapter (evrus-v0):** Core RPC env alias `EVR_RPC_PASS` → `EVR_RPC_PASSWORD`. An EVRUS offer may be translated into an **unsigned MAX publish draft**. The maker must re-sign with a MAX identity after reviewing exact integer quantities. Source tree: `evrus-v0` (not the production-1.0 `evrus` cutdown).

**PeerWeave:** no MAX marketplace client. Spaces, receipts, and libp2p circuit relay remain the PeerWeave product. A future Port that *displays* MAX public search would be a client of `GET /api/search`, not a shared library.

---

## 3. Integration Architecture

### 3.1 Design Principles

1. **Protocol boundaries only.** Sentinel is Rust; PeerWeave is Rust+TS/Tauri; EVRUS is TypeScript/Electron. Integration happens over HTTP, GraphQL, and JSON-RPC — never shared library imports.

2. **Connectors are optional.** Sentinel works standalone with zero ecosystem dependencies. Each connector is behind a feature flag and runtime configuration. `cargo build` without features produces today's standalone binary.

3. **No new protocols.** Every integration uses an API surface that already exists in the target project (PeerWeave's GraphQL HTTP, EVRUS's OIDC bridge, Evrmore's JSON-RPC). We add clients in Sentinel, not new servers in the other projects.

4. **Identity flows downhill.** EVRUS is the identity authority. PeerWeave trusts EVRUS-issued DIDs (via `.evr` aliasing or direct `did:key` mapping). Sentinel accepts EVRUS-issued OIDC tokens for operator authentication.

5. **Data flows uphill.** Sentinel produces telemetry. PeerWeave's graph stores it. Operators query it through either Sentinel's dashboard or PeerWeave's graph explorer.

6. **Audit is append-only and anchorable.** Sentinel's local JSONL audit trail remains the source of truth. Periodic Merkle roots can be anchored to Evrmore through EVRUS's existing transaction pipeline for tamper evidence.

### 3.2 System Diagram

```text
┌──────────────────────────────────────────────────────────────┐
│                    MANTICORE SENTINEL                         │
│                                                              │
│  ┌────────────┐  ┌───────────┐  ┌─────────────────────────┐ │
│  │ Collectors  │  │  Engine   │  │      Dashboard (egui)   │ │
│  │ cpu/mem/    │  │ snapshot  │  │  System | PW | EVRUS    │ │
│  │ disk/net/   │  │ + audit   │  │  views  + connectors    │ │
│  │ process     │  │           │  │  status panel           │ │
│  └──────┬──────┘  └─────┬────┘  └────────────┬────────────┘ │
│         │               │                     │              │
│  ┌──────┴───────────────┴─────────────────────┴────────────┐ │
│  │                  CONNECTOR LAYER                         │ │
│  │                                                          │ │
│  │  ┌─────────────────────┐   ┌──────────────────────────┐ │ │
│  │  │  PeerWeave Client   │   │    EVRUS Client          │ │ │
│  │  │                     │   │                          │ │ │
│  │  │  • GraphQL query    │   │  • OIDC token validate   │ │ │
│  │  │    (node health,    │   │  • Policy evaluation     │ │ │
│  │  │     peer count,     │   │    (action gating)       │ │ │
│  │  │     space state)    │   │  • Evrmore JSON-RPC      │ │ │
│  │  │  • Graph ingest     │   │    (audit anchoring)     │ │ │
│  │  │    (publish system  │   │                          │ │ │
│  │  │     snapshots as    │   │                          │ │ │
│  │  │     graph triples)  │   │                          │ │ │
│  │  └──────────┬──────────┘   └────────────┬─────────────┘ │ │
│  └─────────────┼───────────────────────────┼───────────────┘ │
└────────────────┼───────────────────────────┼─────────────────┘
                 │                           │
        HTTP/GraphQL                  HTTP/JSON-RPC
                 │                           │
                 ▼                           ▼
┌────────────────────────┐    ┌──────────────────────────────┐
│      PeerWeave         │    │        EVRUS Vault           │
│                        │    │                              │
│  GraphQL HTTP API      │    │  OIDC bridge (:8790)         │
│  (:port, CapToken)     │    │  Evrmore JSON-RPC (via node) │
│                        │    │  Policy engine               │
│  libp2p P2P mesh       │    │  libp2p P2P mesh             │
│  CRDT spaces + graph   │    │  Keystore + wallet           │
└────────────────────────┘    └──────────────────────────────┘
                 │                           │
                 │       libp2p Gossipsub    │
                 └───────────────────────────┘
                              │
                              ▼
                 ┌────────────────────────┐
                 │    Evrmore Blockchain   │
                 │    (JSON-RPC :8819)     │
                 └────────────────────────┘
```

### 3.3 What Sentinel Does NOT Become

- Sentinel does not become a PeerWeave node. It does not join Gossipsub meshes, sync CRDTs, or run the PeerWeave protocol. It is a **client** of PeerWeave's GraphQL API.
- Sentinel does not become an Evrmore wallet. It does not hold keys or sign transactions. It delegates anchoring to EVRUS or directly to an Evrmore node via JSON-RPC for simple OP_RETURN writes.
- Sentinel does not become an Electron app. It stays Rust + egui.
- Sentinel does not require PeerWeave or EVRUS to function. Every connector is opt-in.

---

## 4. Connector Specifications

### 4.1 Connector Module Design (Sentinel-side)

New module: `src/connectors/mod.rs`

```rust
pub trait Connector: Send + Sync {
    fn name(&self) -> &str;
    fn status(&self) -> ConnectorStatus;
    fn health_check(&self) -> impl Future<Output = Result<ConnectorHealth>>;
    fn collect(&self) -> impl Future<Output = Result<ConnectorSnapshot>>;
}

pub enum ConnectorStatus {
    Disabled,
    Connecting,
    Healthy,
    Degraded(String),
    Failed(String),
}

pub struct ConnectorHealth {
    pub name: String,
    pub status: ConnectorStatus,
    pub latency_ms: Option<f64>,
    pub detail: Option<String>,
}

pub struct ConnectorSnapshot {
    pub name: String,
    pub timestamp: u64,
    pub data: serde_json::Value,
}
```

Connectors are instantiated at startup based on environment configuration. The `SentinelEngine` collects from both its existing Linux collectors and any active connectors on each refresh cycle. The dashboard renders connector data in dedicated panels.

### 4.2 PeerWeave Connector

**Protocol:** HTTP GET/POST to PeerWeave's GraphQL endpoint.

**Authentication:** `Authorization: Bearer <CapToken>` with `graph.read` scope (and optionally per-space scope). This is the same auth mechanism PeerWeave already implements in `apps/desktop/src-tauri/src/capauth.rs`. Alternatively, use `PW_GRAPHQL_TOKEN` environment variable for development.

**Configuration (Sentinel env vars):**

| Variable | Required | Description |
|----------|----------|-------------|
| `MANTICORE_PEERWEAVE_ENABLED` | No | `true` to activate connector (default `false`) |
| `MANTICORE_PEERWEAVE_GRAPHQL_URL` | When enabled | PeerWeave GraphQL endpoint (e.g. `http://localhost:3200/graphql`) |
| `MANTICORE_PEERWEAVE_CAP_TOKEN` | When enabled | CapToken for `graph.read` scope |
| `MANTICORE_PEERWEAVE_POLL_MS` | No | Polling interval (default `5000`, range `1000..=30000`) |

**Read path (PeerWeave → Sentinel):**

Sentinel queries PeerWeave's GraphQL API for node health metrics:

```graphql
query SentinelHealthCheck {
  node {
    peerId
    status
    uptime
    peers { count }
  }
  spaces {
    id
    name
    syncState
    opsCount
    lastSyncMs
  }
  graph {
    nodeCount
    edgeCount
  }
}
```

The exact GraphQL schema depends on what PeerWeave exposes. The connector handles missing fields gracefully (PeerWeave's schema may evolve). Sentinel never requires PeerWeave to add Sentinel-specific endpoints.

**Write path (Sentinel → PeerWeave graph):**

Sentinel publishes system snapshots as graph triples into a designated PeerWeave space. This makes host telemetry queryable through PeerWeave's graph explorer and available to PeerWeave agents.

Proposed triple structure:

```
(host:<hostname>, type, sentinel:Host)
(host:<hostname>, sentinel:cpuUsage, <float>)
(host:<hostname>, sentinel:memoryUsedBytes, <int>)
(host:<hostname>, sentinel:diskReadBytesPerSec, <int>)
(host:<hostname>, sentinel:networkTxBytesPerSec, <int>)
(host:<hostname>, sentinel:processCount, <int>)
(host:<hostname>, sentinel:snapshotTimestamp, <unix_ms>)
(host:<hostname>, sentinel:trustMode, <string>)
```

This uses PeerWeave's existing graph ingestion path (GraphQL mutation or future ingest API). The write path is a later phase — read-only observation comes first.

**Multi-host story:**

When multiple Sentinel instances publish to the same PeerWeave space, PeerWeave's CRDT engine handles convergence. An operator can query "show me CPU usage across all hosts" through PeerWeave's graph, or see a fleet-wide summary in any Sentinel instance that reads from that space.

### 4.3 EVRUS Connector

**Protocol:** HTTP to EVRUS OIDC bridge and/or Evrmore JSON-RPC.

**Authentication flow:**

1. Operator starts Sentinel with `MANTICORE_AUTH_MODE=evrus`
2. Sentinel fetches OIDC discovery from EVRUS bridge (`/.well-known/openid-configuration`)
3. Sentinel fetches JWKS from the bridge (`/jwks.json`)
4. Operator provides a JWT (issued by EVRUS Vault during login/consent flow)
5. Sentinel validates the JWT: EdDSA signature check against JWKS, expiry, audience
6. Validated JWT claims provide operator identity (DID), role, and capability scope
7. All audit events now carry the EVRUS DID as the actor identity

This replaces the current `MANTICORE_AUTH_TOKEN` env-var approach with real cryptographic identity. The existing `local` and `token` auth modes remain for standalone/development use.

**Configuration (Sentinel env vars):**

| Variable | Required | Description |
|----------|----------|-------------|
| `MANTICORE_EVRUS_ENABLED` | No | `true` to activate connector (default `false`) |
| `MANTICORE_EVRUS_OIDC_URL` | When enabled | EVRUS OIDC bridge URL (e.g. `http://localhost:8790`) |
| `MANTICORE_EVRUS_JWT` | When enabled | JWT issued by EVRUS for this operator session |
| `MANTICORE_EVRUS_ANCHOR_ENABLED` | No | `true` to enable audit trail anchoring |
| `MANTICORE_EVRUS_RPC_URL` | When anchoring | Evrmore node JSON-RPC URL |
| `MANTICORE_EVRUS_RPC_USER` | When anchoring | Evrmore RPC auth user |
| `MANTICORE_EVRUS_RPC_PASS` | When anchoring | Evrmore RPC auth password |

**Identity validation:**

EVRUS's OIDC bridge already serves:
- `/.well-known/openid-configuration` — discovery document
- `/jwks.json` — EdDSA public keys
- `/did.json` — DID document

Sentinel needs only a standard OIDC/JWT validation client. No custom protocol. The EVRUS bridge does not need modification for Sentinel integration.

**Policy bridge (future phase):**

EVRUS's policy engine (`packages/policy-engine`) currently evaluates asset transfer policies (royalty enforcement, recipient allowlists, time windows). A future extension defines a "system action policy" schema:

```json
{
  "action": "kill_process",
  "constraints": {
    "allowedRoles": ["admin"],
    "requireCapability": "KillProcess",
    "denyOnHosts": ["production-*"],
    "requireConfirmation": true
  },
  "termsHash": "<sha256>"
}
```

Sentinel fetches the policy (from EVRUS or from Evrmore asset metadata), evaluates it deterministically before allowing privileged actions, and records the policy hash in the audit event. This is a later phase — identity comes first.

**Audit anchoring:**

Sentinel's audit trail is an append-only JSONL file at `.beads/audit/events.jsonl`. To anchor it:

1. Sentinel computes a Merkle root of recent audit events (SHA-256 over canonical JSON)
2. Sentinel sends a JSON-RPC call to Evrmore: `createrawtransaction` with an OP_RETURN output containing the Merkle root (or uses EVRUS's `updateAnchorAssetMetadata` pattern from the existing PeerWeave anchoring contract)
3. The transaction is broadcast and confirmed on-chain
4. Sentinel records the `txid` and `blockheight` back into the audit trail as an anchor event

This follows the same anchoring model already defined in `evrus-v0/docs/peerweave-anchoring-contract.md` — we reuse the receipt format and two-stage attestation pattern rather than inventing a new one.

**Anchoring receipt format (reusing existing contract):**

```json
{
  "version": 1,
  "receipt_id": "<uuid>",
  "provider": "evrmore",
  "bundle_dir": "sentinel-audit",
  "mirror_root_hash": "<merkle_root_of_audit_events>",
  "timestamp_ms": 1712966400000,
  "publisher_did": "did:key:z6Mk...",
  "sig": "<ed25519_base64>"
}
```

This is intentionally compatible with PeerWeave's `AnchorReceiptV1` so that anchored audit trails can be verified by any system that understands the shared receipt format.

---

## 5. Dashboard Integration

### 5.1 Navigation Model

The Sentinel dashboard gains multi-view navigation (aligns with open beads issue `manticore-sentinel-0f7`):

| View | Content | Connector Required |
|------|---------|-------------------|
| **System** | Existing CPU/memory/disk/network/process dashboard | None (standalone) |
| **PeerWeave** | Node health, peer count, space list, graph stats, sync state | PeerWeave connector |
| **EVRUS** | Operator identity, vault lock status, chain height, policy summary | EVRUS connector |
| **Audit** | Enhanced audit trail with identity attribution and anchor status | None (enhanced with connectors) |
| **Connectors** | Health matrix showing status of all integrations | None (always visible) |

When a connector is disabled, its view shows a clear disabled state with instructions for enabling it — not an error.

### 5.2 Trust Badge Extension

The existing trust badge (`READ-ONLY | OPERATOR | PRIVILEGED`) extends to show identity source:

| Mode | Badge |
|------|-------|
| Local auth, no connectors | `LOCAL · OPERATOR` |
| EVRUS identity | `EVRUS · did:key:z6Mk... · ADMIN` |
| EVRUS identity + anchoring | `EVRUS · ANCHORED · ADMIN` |

### 5.3 Audit Panel Enhancement

When EVRUS identity is active, audit events show the operator's DID instead of a generic "operator" actor. When anchoring is active, the panel shows the last anchor timestamp and Evrmore txid.

---

## 6. Cross-Project Contracts

### 6.1 What Sentinel Needs from PeerWeave

| Need | PeerWeave Surface | Exists Today |
|------|------------------|--------------|
| Node health query | GraphQL HTTP API | Yes (`capauth.rs` + `graphql_http.rs`) |
| CapToken authentication | `Authorization: Bearer` header | Yes |
| Graph triple ingestion | GraphQL mutation or ingest API | Partial (schema exists, mutation surface TBD) |
| Space listing | GraphQL query | Yes (desktop wires this) |

**Action required from PeerWeave:** Expose a stable `node` health query in the GraphQL schema if not already present. Sentinel will adapt to whatever schema PeerWeave ships — no PeerWeave changes are blocked on Sentinel.

### 6.2 What Sentinel Needs from EVRUS

| Need | EVRUS Surface | Exists Today |
|------|--------------|--------------|
| JWT validation | OIDC bridge (`/.well-known/openid-configuration`, `/jwks.json`) | Yes (`apps/oidc-bridge`) |
| DID resolution | `/did.json` endpoint | Yes |
| Evrmore JSON-RPC | `packages/evrmore-adapter` patterns | Yes (Sentinel calls Evrmore node directly) |
| Policy evaluation | `packages/policy-engine` | Yes (needs system-action schema extension) |

**Action required from EVRUS:** None for identity integration. For policy bridge, define a system-action policy schema alongside the existing asset-transfer policy schema. For audit anchoring, Sentinel can call Evrmore JSON-RPC directly — no EVRUS intermediary needed.

### 6.3 What PeerWeave and EVRUS Need from Sentinel

| Need | Sentinel Surface | Exists Today |
|------|-----------------|--------------|
| Host health data | Connector write path (graph triples) | No (to be built) |
| Audit trail for verification | `.beads/audit/events.jsonl` | Yes |
| Anchoring receipts | Compatible with `AnchorReceiptV1` | No (to be built, reusing existing format) |

Sentinel is a **client** of the other systems. PeerWeave and EVRUS do not depend on Sentinel for any core functionality. They benefit from Sentinel's telemetry data when it is published to the graph, but they do not require it.

---

## 7. Implementation Phases

### Phase A — Connector Foundation (Sentinel only)

- Add `src/connectors/mod.rs` with `Connector` trait and `ConnectorStatus` enum
- Add connector config parsing to `core::config::load_runtime_config()`
- Add connectors status panel to dashboard
- Wire connector health into engine refresh cycle
- Zero behavior change when no connectors are configured
- **Dependencies:** None on PeerWeave or EVRUS

### Phase B — PeerWeave Read Connector

- Implement HTTP/GraphQL client in `src/connectors/peerweave.rs`
- Query PeerWeave node health on configurable interval
- Display PeerWeave panel in dashboard (peer count, spaces, graph stats)
- Handle PeerWeave being unavailable gracefully (connector shows `Degraded` or `Failed`)
- **Dependencies:** PeerWeave running with GraphQL HTTP enabled

### Phase C — EVRUS Identity Bridge

- Implement OIDC discovery + JWKS fetch in `src/connectors/evrus.rs`
- Add `evrus` auth mode alongside existing `local` and `token` modes
- Validate JWT on each request cycle (check expiry, signature)
- Attribute audit events to EVRUS DID when authenticated
- **Dependencies:** EVRUS Vault running with OIDC bridge enabled

### Phase D — Dashboard Multi-View

- Implement tabbed navigation in `src/app/dashboard.rs`
- System / PeerWeave / EVRUS / Audit / Connectors views
- Extended trust badge with identity source
- Aligns with beads issue `manticore-sentinel-0f7` (UX overhaul)
- **Dependencies:** Phases B and C for full content, but views render in disabled state without them

### Phase E — PeerWeave Graph Ingest

- Implement graph triple publish from Sentinel to PeerWeave
- System snapshots become queryable knowledge graph nodes
- Multi-host fleet view emerges when multiple Sentinels write to the same space
- **Dependencies:** PeerWeave graph mutation API finalized

### Phase F — Audit Anchoring

- Implement Merkle root computation over audit events
- Implement Evrmore JSON-RPC client for OP_RETURN or asset metadata anchoring
- Reuse `AnchorReceiptV1` format from existing PeerWeave anchoring contract
- Record anchor txid/blockheight in audit trail
- **Dependencies:** Evrmore node accessible, EVRUS anchoring patterns stable

### Phase G — Policy Bridge

- Define system-action policy schema (extension of EVRUS policy engine)
- Fetch and evaluate policies before privileged Sentinel actions
- Record policy hash in audit events
- **Dependencies:** EVRUS policy engine extended with system-action schema

---

## 8. Shared Standards

### 8.1 Identity

All three projects converge on **Ed25519** as the baseline key type:
- PeerWeave: `did:key` Ed25519, CapTokens
- EVRUS: Ed25519 keystore, OIDC bridge issuing EdDSA JWTs
- Sentinel: accepts EVRUS JWTs or PeerWeave CapTokens for identity verification

### 8.2 Signing

Canonical JSON (sorted keys, no extra whitespace, UTF-8) signed with Ed25519. This is already the standard in PeerWeave's anchor receipts and EVRUS's policy hashing.

### 8.3 Anchoring

The `AnchorReceiptV1` format defined in `evrus-v0/docs/peerweave-anchoring-contract.md` is the shared receipt format for all anchoring operations — PeerWeave mirror anchoring and Sentinel audit anchoring alike.

### 8.4 Audit Events

Sentinel's JSONL audit format becomes the reference for operational audit events across the ecosystem. Each event includes:

```json
{
  "ts": "<iso8601>",
  "action": "<command_name>",
  "target": "<target_identifier>",
  "result": "<success|denied|error>",
  "actor": "<did_or_role>",
  "policy_hash": "<sha256_if_policy_evaluated>",
  "anchor_txid": "<evrmore_txid_if_anchored>"
}
```

### 8.5 Error Categories

Sentinel's error taxonomy (`collector`, `helper`, `policy`, `config`, `runtime`) extends with:
- `connector.peerweave` — PeerWeave connector failures
- `connector.evrus` — EVRUS connector failures
- `connector.anchor` — Anchoring failures

---

## 9. What This Document Does NOT Cover

- **PeerWeave ↔ EVRUS direct interop.** That is covered by `evrus-v0/docs/peerweave-interop.md` and the anchoring contract/decision documents. This document references those contracts but does not redefine them.
- **Explorer, GLYPH, or evrmore-rpc integration.** Those products may integrate with Sentinel later, but are out of scope for this design.
- **PeerWeave agent behavior.** How PeerWeave agents use Sentinel telemetry from the graph is a PeerWeave-side design decision, not a Sentinel contract.
- **EVRUS UI changes.** EVRUS does not need UI modifications for Sentinel integration. The OIDC bridge and Evrmore node are the only touch points.
- **Deployment topology.** How many Sentinels, PeerWeave nodes, and EVRUS vaults run on a given host or fleet is an operational decision, not an architectural one.

---

## 10. Modularity Guarantee

Sentinel's value proposition as a standalone Linux observability tool is preserved unconditionally:

- `cargo build` without connector features produces the same binary that exists today
- `cargo run` with no `MANTICORE_PEERWEAVE_ENABLED` or `MANTICORE_EVRUS_ENABLED` env vars runs the standalone dashboard with zero network calls
- All existing auth modes (`local`, `token`) continue to work
- All existing commands, helper boundary, audit trail behavior is unchanged
- Connector code lives in `src/connectors/`, completely isolated from `src/core/`, `src/collectors/`, and `src/security/`

The connector layer is additive. It never subtracts from the standalone product.

---

## 11. Success Criteria

The integration is successful when:

1. An operator can run Sentinel on a host, see Linux system health, and take no ecosystem dependency — **exactly as today**.
2. The same operator can enable PeerWeave connector and see PeerWeave node health alongside system metrics.
3. The same operator can authenticate with an EVRUS-issued identity and have audit events attributed to their DID.
4. Multiple Sentinel instances publishing to the same PeerWeave space produce a queryable fleet-wide view of host health.
5. Audit trail Merkle roots anchored to Evrmore can be independently verified by replaying the JSONL and checking the on-chain hash.
6. None of this breaks if PeerWeave or EVRUS is unavailable — connectors degrade gracefully.
7. Hybrid search (FTS5 + local vectors) and observability HTTP can run headless via `--headless` or `docker compose --profile stack up -d`, with each Compose service optional.

---

## 12. References

### Sentinel
- `docs/truth.md` — Product design document (standalone architecture)
- `docs/auth-rbac-model.md` — Current auth/RBAC model
- `docs/security-threat-model.md` — Threat model and trust boundaries

### PeerWeave
- `peer-weave-app/docs/ARCHITECTURE.md` — Implementation architecture
- `docs/PeerWeave_v0.1_Interoperability_Profile.md` — v0.1 wire protocol
- `peer-weave-app/docs/ONBOARDING_IDENTITY.md` — Identity model
- `peer-weave-app/docs/CONFIG_AND_STORAGE.md` — Config and storage paths

### EVRUS
- `docs/peerweave-interop.md` — PeerWeave ↔ EVRUS interop notes
- `docs/peerweave-anchoring-contract.md` — Anchoring receipt format
- `docs/peerweave-anchoring-decision.md` — Anchoring option decision
- `docs/asset-policy-wallet.md` — Policy engine context

### Cross-Project
- This document — canonical location `manticore-sentinel/docs/manticore-ecosystem-integration.md`
