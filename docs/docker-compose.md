# Docker Compose lab stack

The Compose file at the repository root is a **local evaluation stack**, not a
production deployment. Each service is optional (Compose profiles). Sentinel
connectors degrade if a peer is absent.

## Profiles

| Profile | Services |
|---------|----------|
| `sentinel` | Headless Sentinel (telemetry, SQLite, observability HTTP, SSE) |
| `peerweave` | GraphQL stand-in (not real PeerWeave) |
| `evrus` | OIDC discovery stand-in (not real EVRUS) |
| `observe` | Loopback 302 helper toward Sentinel |
| `stack` | All of the above |

```bash
cp .env.example .env          # optional; gitignored
docker compose --profile stack up -d
docker compose --profile sentinel up -d
docker compose --profile peerweave --profile evrus up -d
```

## Network exposure

| Listener | In-container bind | Host publish |
|----------|-------------------|--------------|
| Sentinel observability `9463` | `0.0.0.0` (so Compose DNS works) | `127.0.0.1:9463` |
| Sentinel SSE `9462` | process default | `127.0.0.1:9462` |
| PeerWeave stand-in `3200` | `0.0.0.0` | `127.0.0.1:3200` |
| EVRUS OIDC stand-in `8790` | `0.0.0.0` | `127.0.0.1:8790` |
| Observe redirect `8088` | `0.0.0.0` | `127.0.0.1:8088` |

Do not change host publishes to `0.0.0.0` unless every listener has
authentication and you accept internet or LAN exposure.

The GraphQL stand-in is **unauthenticated when `PW_GRAPHQL_TOKEN` is empty**.
Set `MANTICORE_PEERWEAVE_CAP_TOKEN` in `.env` for even a local lab if other
containers on the Compose network should not write snapshots.

## Host PID namespace

`sentinel` uses `pid: host` so collectors can see host processes. That is
Linux-only and expands the container's view of the host. The service is not
given `privileged: true`. `no-new-privileges` is set.

## Data

SQLite lives in the `sentinel-data` volume at `/var/lib/manticore/sentinel.sqlite`.
Treat that volume as sensitive (process names, logs, search documents).

## Replacing stand-ins

Point Sentinel at real services instead of the stubs:

```bash
MANTICORE_PEERWEAVE_GRAPHQL_URL=http://127.0.0.1:3200/graphql
MANTICORE_PEERWEAVE_CAP_TOKEN=...          # from PeerWeave
MANTICORE_EVRUS_OIDC_URL=http://127.0.0.1:8790
MANTICORE_EVRUS_JWT=...                    # from EVRUS
```

Protocol contract: [manticore-ecosystem-integration.md](manticore-ecosystem-integration.md).
