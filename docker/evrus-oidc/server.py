#!/usr/bin/env python3
"""Optional EVRUS OIDC stand-in for the Manticore stack.

Serves the discovery document Sentinel probes. Replace with the real
evrus-v0 oidc-bridge when running the full vault.
"""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

PORT = int(os.environ.get("PORT", "8790"))
ISSUER = os.environ.get("OIDC_ISSUER_URL", f"http://127.0.0.1:{PORT}")
DID = os.environ.get("EVRUS_SIOP_ISS", "did:key:z6MkDemo")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        print(f"evrus-oidc: {fmt % args}")

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in ("/health", "/"):
            self._json(200, {"ok": True, "service": "evrus-oidc", "did": DID})
            return
        if path == "/.well-known/openid-configuration":
            self._json(
                200,
                {
                    "issuer": ISSUER,
                    "jwks_uri": f"{ISSUER}/jwks.json",
                    "authorization_endpoint": f"{ISSUER}/authorize",
                    "token_endpoint": f"{ISSUER}/token",
                    "id_token_signing_alg_values_supported": ["EdDSA"],
                    "subject_types_supported": ["public"],
                    "response_types_supported": ["id_token"],
                },
            )
            return
        if path == "/jwks.json":
            self._json(200, {"keys": []})
            return
        if path == "/did.json":
            self._json(200, {"id": DID, "verificationMethod": []})
            return
        self._json(404, {"error": "not found"})


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"evrus-oidc listening on {PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
