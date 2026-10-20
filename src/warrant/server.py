"""MCP server: tools, per-tool scopes, and the HTTP app."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.routes import create_protected_resource_routes
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS, ToolAnnotations
from pydantic import AnyHttpUrl
from starlette.applications import Starlette

from warrant.store import Note, NoteStore

READ = "notes:read"
WRITE = "notes:write"
SCOPES = [READ, WRITE]

# Implementation-defined JSON-RPC range (-32000..-32019).
INSUFFICIENT_SCOPE = -32010


def _caller() -> str:
    token = get_access_token()
    if token is None or not token.subject:
        # Unreachable behind the SDK's auth middleware; guards a server built without it.
        raise ToolError("unauthenticated")
    return token.subject


def build_server(
    store: NoteStore, verifier: TokenVerifier, *, issuer: str, resource_url: str
) -> MCPServer:
    tool_scopes: dict[str, str] = {}

    async def scope_gate(ctx: Any, call_next: Callable) -> Any:
        if ctx.method == "tools/call":
            # Raw params: this runs before the SDK validates them.
            params = ctx.params if isinstance(ctx.params, dict) else {}
            name = params.get("name")
            required = tool_scopes.get(name) if isinstance(name, str) else None
            if required is None:
                # Unknown, or registered without a scope: fail closed.
                raise MCPError(INVALID_PARAMS, f"unknown tool: {name}")
            token = get_access_token()
            if token is None or required not in token.scopes:
                raise MCPError(INSUFFICIENT_SCOPE, f"insufficient_scope: requires {required}")
        return await call_next(ctx)

    server = MCPServer(
        "warrant",
        token_verifier=verifier,
        auth=AuthSettings(
            issuer_url=issuer,
            resource_server_url=resource_url,
            validate_token_resource=False,  # JwtVerifier checks aud
        ),
        middleware=[scope_gate],
    )

    def tool(scope: str, *, read_only: bool) -> Callable:
        """Register a tool together with its required scope."""

        def register(fn: Callable) -> Callable:
            tool_scopes[fn.__name__] = scope
            return server.tool(annotations=ToolAnnotations(read_only_hint=read_only))(fn)

        return register

    @tool(READ, read_only=True)
    def search_notes(query: str = "", limit: int = 10) -> list[Note]:
        """Search your notes by substring of title or body. An empty query lists the most recent."""
        return store.search(_caller(), query, limit)

    @tool(READ, read_only=True)
    def get_note(note_id: int) -> Note:
        """Fetch one of your notes by id."""
        note = store.get(_caller(), note_id)
        if note is None:
            raise ToolError(f"note {note_id} not found")
        return note

    @tool(WRITE, read_only=False)
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
    app = server.streamable_http_app(host=host)
    # The SDK's metadata route lists only global required_scopes. Ours goes first
    # and lists every tool scope, so clients request them at login.
    app.router.routes[0:0] = create_protected_resource_routes(
        resource_url=AnyHttpUrl(resource_url),
        authorization_servers=[AnyHttpUrl(issuer)],
        scopes_supported=SCOPES,
    )
    return app
