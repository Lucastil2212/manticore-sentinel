# Realtime data, search, and ecosystem stack

Sentinel's UI must never wait on durable storage, vector indexing, or remote connector I/O. The operational split is:

1. **Hot path:** Linux collectors -> in-memory snapshot -> egui render.
2. **Warm path:** bounded queues -> local durable history/audit.
3. **Discovery path:** events/documents -> Search service -> SQLite FTS5; optional Qdrant vector index.
4. **Ecosystem path:** PeerWeave and EVRUS remain independent optional services reached over protocol boundaries.

## Hybrid search

The search sidecar stores canonical text and metadata in SQLite with WAL enabled and an FTS5 index. When Qdrant is enabled it also stores a deterministic sparse projection for vector similarity. Query results fuse lexical and vector scores. Qdrant failure degrades to FTS rather than making discovery unavailable.

The deterministic projection is deliberately model-free: it makes the service portable and useful on a Raspberry Pi or laptop. A learned embedding provider can replace it later without changing the API.

## Run

Core FTS service only:

```bash
docker compose --profile search up -d --build
```

Hybrid FTS + vector:

```bash
docker compose --profile search --profile vector up -d --build
```

Add PeerWeave and EVRUS testnet infrastructure:

```bash
PEERWEAVE_DIR=../peer-weave EVRUS_DIR=../evrus-v0 \
docker compose --profile search --profile vector --profile peerweave --profile evrus up -d --build
```

Each profile is optional. There is intentionally no `depends_on` chain between products: a missing PeerWeave, EVRUS, Qdrant, or search service must not stop the others.

## API

- `GET /health`
- `POST /v1/documents` — idempotent upsert by document ID.
- `GET /v1/search?q=...&limit=20` — FTS or hybrid retrieval.

Recommended document kinds are `system_snapshot`, `audit_event`, `connector_event`, `log`, `peerweave_node`, and `evrus_asset`.

## PeerWeave contract correction

Current PeerWeave desktop GraphQL defaults to loopback port **49152**, requires a shared token or CapToken, and exposes graph queries such as `stats`, `search`, `allNodes`, and `allEdges`. It does **not** expose the old Sentinel-specific `node/spaces/graph` query or `sentinelIngestSnapshot` mutation. Sentinel therefore treats PeerWeave as an optional read/query integration until a supported ingestion endpoint exists.

The PeerWeave CLI container exposes its P2P/gateway service, not the desktop GraphQL server. For GraphQL integration, run the PeerWeave desktop backend on the host and point Sentinel at `http://127.0.0.1:49152/graphql`.

## Performance rules

- No network request on the egui render thread.
- No whole-history rewrite on each sample.
- Bound all in-memory histories and queues.
- Prefer WAL/batched commits for local indexes.
- Render sampled/downsampled chart points rather than unbounded raw series.
- Cache connector state and update it on slower cadences.
