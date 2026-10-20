from __future__ import annotations

import functools
from contextlib import asynccontextmanager

import httpx2
import pytest
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client

from warrant.auth import JwtVerifier
from warrant.dev import DevIssuer
from warrant.server import build_app
from warrant.store import NoteStore

ISSUER = "https://issuer.test/"
RESOURCE = "http://testserver/mcp"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def issuer():
    issuer = DevIssuer(RESOURCE, issuer=ISSUER)
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
async def open_client(app, token: str, mode: str = "auto"):
    """MCP client to an in-process app, authenticated with `token`."""
    http = httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app),
        base_url="http://testserver",
        headers={"Authorization": f"Bearer {token}"},
    )
    transport = streamable_http_client(RESOURCE, http_client=http)
    async with http, Client(transport, mode=mode) as client:
        yield client


@pytest.fixture
def connect(app):
    return functools.partial(open_client, app)


@pytest.fixture
def raw(app):
    """Plain HTTP client to the app, for asserting on status codes and headers."""
    return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://testserver")
