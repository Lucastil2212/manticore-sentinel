import asyncio
import hashlib
import json
import math
import os
import re
import sqlite3
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

DB_PATH = Path(os.getenv("SENTINEL_SEARCH_DB", "/data/search.db"))
QDRANT_URL = os.getenv("QDRANT_URL", "").rstrip("/")
QDRANT_COLLECTION = os.getenv("QDRANT_COLLECTION", "sentinel")
VECTOR_DIM = int(os.getenv("SENTINEL_VECTOR_DIM", "384"))
MAX_BODY = int(os.getenv("SENTINEL_MAX_DOCUMENT_BYTES", "262144"))
TOKEN_RE = re.compile(r"[A-Za-z0-9_./:@-]+")
db_lock = asyncio.Lock()


def db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db() -> None:
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS documents (
      id TEXT PRIMARY KEY,
      source TEXT NOT NULL,
      kind TEXT NOT NULL,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      metadata TEXT NOT NULL DEFAULT '{}',
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
      id UNINDEXED, title, body, source, kind,
      tokenize='unicode61 remove_diacritics 2'
    );
    CREATE INDEX IF NOT EXISTS documents_updated_idx ON documents(updated_at DESC);
    CREATE INDEX IF NOT EXISTS documents_source_idx ON documents(source, kind);
    """)
    conn.commit()
    conn.close()


def sparse_embedding(text: str) -> list[float]:
    vector = [0.0] * VECTOR_DIM
    for token in TOKEN_RE.findall(text.lower()):
        digest = hashlib.blake2b(token.encode(), digest_size=8).digest()
        value = int.from_bytes(digest, "little")
        idx = value % VECTOR_DIM
        vector[idx] += -1.0 if (value >> 63) else 1.0
    norm = math.sqrt(sum(v * v for v in vector)) or 1.0
    return [v / norm for v in vector]


async def qdrant_upsert(doc_id: str, text: str, payload: dict[str, Any]) -> None:
    if not QDRANT_URL:
        return
    point_id = hashlib.sha256(doc_id.encode()).hexdigest()[:32]
    body = {"points": [{"id": point_id, "vector": sparse_embedding(text), "payload": {"doc_id": doc_id, **payload}}]}
    async with httpx.AsyncClient(timeout=2.0) as client:
        await client.put(f"{QDRANT_URL}/collections/{QDRANT_COLLECTION}/points?wait=false", json=body)


async def qdrant_search(text: str, limit: int) -> list[tuple[str, float]]:
    if not QDRANT_URL:
        return []
    async with httpx.AsyncClient(timeout=2.0) as client:
        response = await client.post(
            f"{QDRANT_URL}/collections/{QDRANT_COLLECTION}/points/search",
            json={"vector": sparse_embedding(text), "limit": limit, "with_payload": True},
        )
        response.raise_for_status()
        return [
            (str(item.get("payload", {}).get("doc_id", "")), float(item.get("score", 0.0)))
            for item in response.json().get("result", [])
            if item.get("payload", {}).get("doc_id")
        ]


async def ensure_qdrant() -> None:
    if not QDRANT_URL:
        return
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.put(
                f"{QDRANT_URL}/collections/{QDRANT_COLLECTION}",
                json={"vectors": {"size": VECTOR_DIM, "distance": "Cosine"}},
            )
    except Exception:
        pass


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    await ensure_qdrant()
    yield


app = FastAPI(title="Manticore Sentinel Search", version="0.2.0", lifespan=lifespan)


class Document(BaseModel):
    id: str = Field(min_length=1, max_length=256)
    source: str = Field(default="sentinel", max_length=128)
    kind: str = Field(default="event", max_length=64)
    title: str = Field(default="", max_length=512)
    body: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: int | None = None


@app.get("/health")
async def health():
    return {"ok": True, "storage": str(DB_PATH), "vector": bool(QDRANT_URL), "vector_dim": VECTOR_DIM}


@app.post("/v1/documents")
async def ingest(document: Document):
    if len(document.body.encode()) > MAX_BODY:
        raise HTTPException(413, "document too large")
    now = document.timestamp or int(time.time())
    metadata = json.dumps(document.metadata, separators=(",", ":"), sort_keys=True)
    async with db_lock:
        conn = db()
        try:
            conn.execute(
                """INSERT INTO documents(id,source,kind,title,body,metadata,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET source=excluded.source,kind=excluded.kind,title=excluded.title,
                   body=excluded.body,metadata=excluded.metadata,updated_at=excluded.updated_at""",
                (document.id, document.source, document.kind, document.title, document.body, metadata, now, now),
            )
            conn.execute("DELETE FROM documents_fts WHERE id=?", (document.id,))
            conn.execute(
                "INSERT INTO documents_fts(id,title,body,source,kind) VALUES(?,?,?,?,?)",
                (document.id, document.title, document.body, document.source, document.kind),
            )
            conn.commit()
        finally:
            conn.close()
    try:
        await qdrant_upsert(document.id, f"{document.title}\n{document.body}", {"source": document.source, "kind": document.kind})
    except Exception:
        pass
    return {"accepted": True, "id": document.id}


def normalize_fts(query: str) -> str:
    tokens = TOKEN_RE.findall(query)
    if not tokens:
        return '""'
    return " OR ".join(f'"{token.replace(chr(34), "")}"' for token in tokens[:24])


@app.get("/v1/search")
async def search(q: str = Query(min_length=1, max_length=512), limit: int = Query(20, ge=1, le=100)):
    conn = db()
    try:
        rows = conn.execute(
            """SELECT d.*, bm25(documents_fts, 1.5, 1.0, 0.3, 0.2) AS rank
               FROM documents_fts JOIN documents d ON d.id=documents_fts.id
               WHERE documents_fts MATCH ? ORDER BY rank LIMIT ?""",
            (normalize_fts(q), limit * 3),
        ).fetchall()
    finally:
        conn.close()
    lexical = {row["id"]: (row, 1.0 / (1.0 + max(0.0, float(row["rank"])))) for row in rows}
    try:
        vector = await qdrant_search(q, limit * 3)
    except Exception:
        vector = []
    vector_scores = dict(vector)
    ids = set(lexical) | set(vector_scores)
    scored = []
    for doc_id in ids:
        lexical_score = lexical.get(doc_id, (None, 0.0))[1]
        vector_score = max(0.0, vector_scores.get(doc_id, 0.0))
        scored.append((0.58 * lexical_score + 0.42 * vector_score, doc_id))
    scored.sort(reverse=True)
    missing = [doc_id for _, doc_id in scored[:limit] if doc_id not in lexical]
    extra = {}
    if missing:
        conn = db()
        try:
            marks = ",".join("?" for _ in missing)
            extra = {row["id"]: row for row in conn.execute(f"SELECT * FROM documents WHERE id IN ({marks})", missing)}
        finally:
            conn.close()
    results = []
    for score, doc_id in scored[:limit]:
        row = lexical.get(doc_id, (None, 0.0))[0] or extra.get(doc_id)
        if row is None:
            continue
        results.append({
            "id": doc_id, "score": round(score, 6), "source": row["source"], "kind": row["kind"],
            "title": row["title"], "body": row["body"], "metadata": json.loads(row["metadata"]),
            "updated_at": row["updated_at"],
        })
    return {"query": q, "mode": "hybrid" if QDRANT_URL else "fts", "results": results}
