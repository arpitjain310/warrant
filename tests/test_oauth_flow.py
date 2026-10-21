"""The full OAuth flow, driven by the SDK's own client: discovery, a minimal
login, a 403 step-up to write, and the retry.

The authorization server is a stub that approves every request for one user and
signs with the DevIssuer key. It checks PKCE and the RFC 8707 resource, so the
client has to run the real flow to get a token.
"""

import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlparse

import anyio
import httpx2
import jwt
import pytest
from mcp.client import Client
from mcp.client.auth import OAuthClientProvider
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import AuthorizationCodeResult, OAuthClientMetadata

from .conftest import ISSUER, RESOURCE

pytestmark = pytest.mark.anyio


class StubAuthorizationServer:
    def __init__(self, issuer, user: str = "alice"):
        self.issuer = issuer
        self.user = user
        self.grants: list[str] = []  # requested scope, per authorization
        self._codes: dict[str, dict] = {}

    def authorize(self, url: str) -> AuthorizationCodeResult:
        """The browser leg: the user approves and the redirect carries a code."""
        query = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
        code = secrets.token_urlsafe(16)
        self._codes[code] = query
        self.grants.append(query.get("scope", ""))
        return AuthorizationCodeResult(code=code, state=query["state"], iss=ISSUER)

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        path = request.url.path
        if path in ("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"):
            return httpx2.Response(200, json=self._metadata())
        if path == "/token":
            return self._token(request)
        return httpx2.Response(404)

    def _metadata(self) -> dict:
        return {
            "issuer": ISSUER,
            "authorization_endpoint": ISSUER + "authorize",
            "token_endpoint": ISSUER + "token",
            "code_challenge_methods_supported": ["S256"],
            "client_id_metadata_document_supported": True,
            "authorization_response_iss_parameter_supported": True,
        }

    def _token(self, request: httpx2.Request) -> httpx2.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        grant = self._codes.pop(form.get("code", ""), None)
        if grant is None:
            return httpx2.Response(400, json={"error": "invalid_grant"})
        digest = hashlib.sha256(form.get("code_verifier", "").encode()).digest()
        if base64.urlsafe_b64encode(digest).rstrip(b"=").decode() != grant["code_challenge"]:
            return httpx2.Response(400, json={"error": "invalid_grant"})
        resource = grant.get("resource")
        if resource is None or form.get("resource") != resource:
            return httpx2.Response(400, json={"error": "invalid_target"})
        scope = grant.get("scope", "")
        token = self.issuer.mint(self.user, tuple(scope.split()), aud=resource)
        return httpx2.Response(
            200,
            json={
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": scope,
            },
        )


class MemoryStorage:
    def __init__(self):
        self.tokens = None
        self.client_info = None

    async def get_tokens(self):
        return self.tokens

    async def set_tokens(self, tokens):
        self.tokens = tokens

    async def get_client_info(self):
        return self.client_info

    async def set_client_info(self, client_info):
        self.client_info = client_info


async def test_client_logs_in_minimally_then_steps_up_to_write(app, issuer):
    stub = StubAuthorizationServer(issuer)
    storage = MemoryStorage()
    redirects: list[AuthorizationCodeResult] = []

    async def redirect_handler(url: str) -> None:
        redirects.append(stub.authorize(url))

    async def callback_handler() -> AuthorizationCodeResult:
        return redirects.pop()

    auth = OAuthClientProvider(
        server_url=RESOURCE,
        client_metadata=OAuthClientMetadata(
            redirect_uris=["http://localhost:3030/callback"],
            grant_types=["authorization_code"],
            response_types=["code"],
            token_endpoint_auth_method="none",
        ),
        storage=storage,
        redirect_handler=redirect_handler,
        callback_handler=callback_handler,
        client_metadata_url="https://client.test/oauth/client.json",
    )
    http = httpx2.AsyncClient(
        auth=auth,
        mounts={
            "http://testserver": httpx2.ASGITransport(app=app),
            ISSUER.rstrip("/"): httpx2.MockTransport(stub.handle),
        },
    )
    # A broken flow can leave the client waiting rather than raising.
    with anyio.fail_after(30):
        await run_flow(http, stub)

    claims = jwt.decode(storage.tokens.access_token, options={"verify_signature": False})
    assert claims["aud"] == RESOURCE
    assert claims["scope"] == "notes:read notes:write"


async def run_flow(http: httpx2.AsyncClient, stub: StubAuthorizationServer) -> None:
    async with http, Client(streamable_http_client(RESOURCE, http_client=http)) as client:
        found = await client.call_tool("search_notes", {"query": ""})
        assert not found.is_error
        # First login asks only for the metadata's baseline.
        assert stub.grants == ["notes:read"]

        created = await client.call_tool("create_note", {"title": "plan", "body": "ship it"})
        assert not created.is_error
        # The 403 triggered one re-authorization for the union of held and challenged scopes.
        assert stub.grants == ["notes:read", "notes:read notes:write"]
