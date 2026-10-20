"""Local token issuer for development and tests.

Not an authorization server: it signs tokens on request and serves its public
keys, so the verifier's real JWKS path runs without an identity provider.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

Key = tuple[str, rsa.RSAPrivateKey]


def new_key() -> Key:
    return uuid.uuid4().hex, rsa.generate_private_key(public_exponent=65537, key_size=2048)


class DevIssuer:
    """Signs RS256 access tokens; serves the JWKS on an ephemeral localhost port."""

    def __init__(self, audience: str, issuer: str | None = None):
        self.keys: list[Key] = [new_key()]
        self.fetches = 0  # JWKS requests served
        dev = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != "/jwks.json":
                    self.send_error(404)
                    return
                dev.fetches += 1
                body = json.dumps(dev.jwks()).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self._http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._http.serve_forever, args=(0.05,), daemon=True).start()
        base = f"http://127.0.0.1:{self._http.server_port}"
        self.jwks_url = base + "/jwks.json"
        self.issuer = issuer or base + "/"
        self.audience = audience

    def close(self) -> None:
        self._http.shutdown()
        self._http.server_close()

    def jwks(self) -> dict:
        keys = []
        for kid, key in self.keys:
            jwk = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
            keys.append({**jwk, "kid": kid, "use": "sig", "alg": "RS256"})
        return {"keys": keys}

    def rotate(self) -> None:
        """Publish a new signing key and sign with it from now on."""
        self.keys.insert(0, new_key())

    def mint(
        self,
        sub: str = "dev",
        scopes: tuple[str, ...] = ("notes:read",),
        *,
        aud: str | list[str] | None = None,
        iss: str | None = None,
        ttl: int = 3600,
        key: Key | None = None,
        **claims,
    ) -> str:
        kid, private_key = key or self.keys[0]
        now = int(time.time())
        payload = {
            "iss": iss or self.issuer,
            "aud": aud or self.audience,
            "sub": sub,
            "iat": now,
            "exp": now + ttl,
            "scope": " ".join(scopes),
            "azp": "dev-client",
            **claims,
        }
        return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})
