from __future__ import annotations

import functools
import json
import threading
import time
import uuid
from contextlib import asynccontextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client

from warrant.auth import JwtVerifier
from warrant.server import build_app
from warrant.store import NoteStore

ISSUER = "https://issuer.test/"
RESOURCE = "http://testserver/mcp"


def new_key() -> tuple[str, rsa.RSAPrivateKey]:
    return uuid.uuid4().hex, rsa.generate_private_key(public_exponent=65537, key_size=2048)


class Issuer:
    """Signs access tokens and serves its JWKS over real HTTP, so the verifier's
    production key-fetch path runs in tests."""

    def __init__(self):
        self.keys = [new_key()]
        self.fetches = 0
        issuer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                issuer.fetches += 1
                body = json.dumps(issuer.jwks()).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self._http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._http.serve_forever, args=(0.05,), daemon=True).start()
        self.jwks_url = f"http://127.0.0.1:{self._http.server_port}/jwks.json"

    def close(self):
        self._http.shutdown()
        self._http.server_close()

    def jwks(self) -> dict:
        keys = []
        for kid, key in self.keys:
            jwk = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
            keys.append({**jwk, "kid": kid, "use": "sig", "alg": "RS256"})
        return {"keys": keys}

    def rotate(self):
        self.keys.insert(0, new_key())

    def mint(
        self,
        sub: str = "alice",
        scopes: tuple[str, ...] = ("notes:read",),
        *,
        aud: str = RESOURCE,
        iss: str = ISSUER,
        ttl: int = 300,
        key: tuple[str, rsa.RSAPrivateKey] | None = None,
        **claims,
    ) -> str:
        kid, private_key = key or self.keys[0]
        now = int(time.time())
        payload = {
            "iss": iss,
            "aud": aud,
            "sub": sub,
            "iat": now,
            "exp": now + ttl,
            "scope": " ".join(scopes),
            "azp": "test-client",
            **claims,
        }
        return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def issuer():
    issuer = Issuer()
    yield issuer
    issuer.close()


@pytest.fixture
def verifier(issuer):
    return JwtVerifier(ISSUER, RESOURCE, issuer.jwks_url)


@pytest.fixture
async def app(verifier):
    app = build_app(NoteStore(), verifier, issuer=ISSUER, resource_url=RESOURCE, host="testserver")
    async with app.router.lifespan_context(app):
        yield app


@asynccontextmanager
async def open_client(app, token: str):
    """MCP client to an in-process app, authenticated with `token`."""
    http = httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app),
        base_url="http://testserver",
        headers={"Authorization": f"Bearer {token}"},
    )
    async with http, Client(streamable_http_client(RESOURCE, http_client=http)) as client:
        yield client


@pytest.fixture
def connect(app):
    return functools.partial(open_client, app)


@pytest.fixture
def raw(app):
    """Plain HTTP client to the app, for asserting on status codes and headers."""
    return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://testserver")
