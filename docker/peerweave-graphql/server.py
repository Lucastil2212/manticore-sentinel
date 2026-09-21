#!/usr/bin/env python3
"""Optional PeerWeave GraphQL stand-in for the Manticore stack.

Implements the read query Sentinel already sends, plus the
sentinelIngestSnapshot mutation. Real PeerWeave can replace this service
without changing Sentinel.
"""
from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = {
    "peer_id": os.environ.get("PW_PEER_ID", "12D3KooWsentineldev0001"),
    "status": "online",
    "started": time.time(),
    "peers": int(os.environ.get("PW_PEER_COUNT", "1")),
    "spaces": [
        {
            "id": os.environ.get("PW_SPACE_ID", "sentinel-space"),
            "name": "sentinel",
            "syncState": "synced",
            "opsCount": 0,
            "lastSyncMs": 0,
        }
    ],
    "graph": {"nodeCount": 8, "edgeCount": 7},
    "accepted": 0,
}
LOCK = threading.Lock()
TOKEN = os.environ.get("PW_GRAPHQL_TOKEN", "").strip()
PORT = int(os.environ.get("PORT", "3200"))


def authorized(handler: BaseHTTPRequestHandler) -> bool:
    if not TOKEN:
        return True
    auth = handler.headers.get("Authorization", "")
    presented = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    alt = handler.headers.get("x-peerweave-token", "")
    return presented == TOKEN or alt == TOKEN


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        print(f"peerweave-graphql: {fmt % args}")

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/health", "/"):
            self._json(200, {"ok": True, "service": "peerweave-graphql"})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not authorized(self):
            self._json(401, {"errors": [{"message": "Unauthorized"}]})
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            self._json(400, {"errors": [{"message": "invalid json"}]})
            return
        query = str(body.get("query") or "")
        with LOCK:
            if "sentinelIngestSnapshot" in query:
                STATE["accepted"] += 1
                STATE["graph"]["nodeCount"] += 1
                STATE["graph"]["edgeCount"] += 1
                STATE["spaces"][0]["opsCount"] = STATE["accepted"]
                self._json(
                    200,
                    {"data": {"sentinelIngestSnapshot": {"accepted": True}}},
                )
                return
            payload = {
                "data": {
                    "node": {
                        "peerId": STATE["peer_id"],
                        "status": STATE["status"],
                        "uptime": int(time.time() - STATE["started"]),
                        "peers": {"count": STATE["peers"]},
                    },
                    "spaces": STATE["spaces"],
                    "graph": STATE["graph"],
                }
            }
        self._json(200, payload)


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"peerweave-graphql listening on {PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
