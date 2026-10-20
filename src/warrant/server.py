"""MCP server: tools, per-tool scopes, and the HTTP app."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.routes import build_resource_metadata_url
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.shared.exceptions import MCPError
from mcp.shared.inbound import MCP_METHOD_HEADER, MCP_NAME_HEADER, decode_header_value
from mcp.types import INVALID_PARAMS, ToolAnnotations
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from warrant.store import Note, NoteStore

READ = "notes:read"
WRITE = "notes:write"

# Every request needs the baseline. It is the only scope in the metadata, so a
# client starts minimal and steps up to WRITE when a tool asks for it.
BASELINE = READ

TOOL_SCOPES = {
    "search_notes": READ,
    "get_note": READ,
    "create_note": WRITE,
}

MCP_PATH = "/mcp"

# Implementation-defined JSON-RPC range (-32000..-32019).
INSUFFICIENT_SCOPE = -32010


def required_scopes(tool: str | None) -> set[str]:
    """Scopes a request needs: the baseline, plus the tool's own on tools/call."""
    needed = {BASELINE}
    if tool in TOOL_SCOPES:
        needed.add(TOOL_SCOPES[tool])
    return needed


class ScopeChallenge:
    """Answers a request the token can't make with 403 and WWW-Authenticate
    scope=, which OAuth clients treat as a step-up.

    The tool comes from the 2026-07-28 Mcp-Method / Mcp-Name headers, which the
    SDK rejects when they disagree with the body. Requests without them still
    meet scope_gate.
    """

    def __init__(self, app: ASGIApp, resource_metadata_url: str):
        self.app = app
        self.resource_metadata_url = resource_metadata_url

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        user = scope.get("user")
        # No user: the SDK answers 401.
        if isinstance(user, AuthenticatedUser):
            headers = Headers(scope=scope)
            tool = None
            if headers.get(MCP_METHOD_HEADER) == "tools/call":
                tool = decode_header_value(headers.get(MCP_NAME_HEADER))
            needed = required_scopes(tool)
            if not needed <= set(user.scopes):
                await self._challenge(needed)(scope, receive, send)
                return
        await self.app(scope, receive, send)

    def _challenge(self, needed: set[str]) -> JSONResponse:
        # All scopes the operation needs, in one challenge.
        scopes = " ".join(sorted(needed))
        description = f"requires {scopes}"
        return JSONResponse(
            {"error": "insufficient_scope", "error_description": description},
            status_code=403,
            headers={
                "WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{scopes}", '
                f'resource_metadata="{self.resource_metadata_url}", '
                f'error_description="{description}"'
            },
        )


async def scope_gate(ctx: Any, call_next: Callable) -> Any:
    """Handler-tier check on every tools/call, whatever headers it came with."""
    if ctx.method == "tools/call":
        # Raw params: this runs before the SDK validates them.
        params = ctx.params if isinstance(ctx.params, dict) else {}
        name = params.get("name")
        required = TOOL_SCOPES.get(name) if isinstance(name, str) else None
        if required is None:
            # Unknown, or registered without a scope: fail closed.
            raise MCPError(INVALID_PARAMS, f"unknown tool: {name}")
        token = get_access_token()
        if token is None or required not in token.scopes:
            raise MCPError(INSUFFICIENT_SCOPE, f"insufficient_scope: requires {required}")
    return await call_next(ctx)


def _caller() -> str:
    token = get_access_token()
    if token is None or not token.subject:
        # Unreachable behind the SDK's auth middleware; guards a server built without it.
        raise ToolError("unauthenticated")
    return token.subject


def build_server(
    store: NoteStore, verifier: TokenVerifier, *, issuer: str, resource_url: str
) -> MCPServer:
    server = MCPServer(
        "warrant",
        token_verifier=verifier,
        auth=AuthSettings(
            issuer_url=issuer,
            resource_server_url=resource_url,
            required_scopes=[BASELINE],
            validate_token_resource=False,  # JwtVerifier checks aud
        ),
        middleware=[scope_gate],
    )
    reads = ToolAnnotations(read_only_hint=True)
    writes = ToolAnnotations(read_only_hint=False)

    @server.tool(annotations=reads)
    def search_notes(query: str = "", limit: int = 10) -> list[Note]:
        """Search your notes by substring of title or body. An empty query lists the most recent."""
        return store.search(_caller(), query, limit)

    @server.tool(annotations=reads)
    def get_note(note_id: int) -> Note:
        """Fetch one of your notes by id."""
        note = store.get(_caller(), note_id)
        if note is None:
            raise ToolError(f"note {note_id} not found")
        return note

    @server.tool(annotations=writes)
    def create_note(title: str, body: str) -> Note:
        """Create a note."""
        return store.create(_caller(), title, body)

    return server


def build_app(
    store: NoteStore,
    verifier: TokenVerifier,
    *,
    issuer: str,
    resource_url: str,
    host: str = "127.0.0.1",
) -> Starlette:
    server = build_server(store, verifier, issuer=issuer, resource_url=resource_url)
    app = server.streamable_http_app(streamable_http_path=MCP_PATH, host=host)
    metadata_url = str(build_resource_metadata_url(AnyHttpUrl(resource_url)))
    # Inside authentication (scope["user"] is set), ahead of the SDK's own scope check.
    route = next(r for r in app.router.routes if isinstance(r, Route) and r.path == MCP_PATH)
    route.app = ScopeChallenge(route.app, metadata_url)
    return app
