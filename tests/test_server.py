import pytest
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS

from warrant.server import INSUFFICIENT_SCOPE, build_server
from warrant.store import NoteStore

from .conftest import ISSUER, RESOURCE, open_client

pytestmark = pytest.mark.anyio

READ = ("notes:read",)
READ_WRITE = ("notes:read", "notes:write")


async def test_unauthenticated_request_gets_401_with_resource_metadata(raw):
    async with raw:
        r = await raw.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r.status_code == 401
    metadata_url = "http://testserver/.well-known/oauth-protected-resource/mcp"
    assert f'resource_metadata="{metadata_url}"' in r.headers["www-authenticate"]


async def test_metadata_names_issuer_and_every_tool_scope(raw):
    async with raw:
        r = await raw.get("/.well-known/oauth-protected-resource/mcp")
    meta = r.json()
    assert meta["resource"] == RESOURCE
    assert meta["authorization_servers"] == [ISSUER]
    assert meta["scopes_supported"] == ["notes:read", "notes:write"]


async def test_token_for_another_audience_gets_401(raw, issuer):
    token = issuer.mint(scopes=READ_WRITE, aud="https://other-api.test/")
    async with raw:
        r = await raw.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 401


async def test_write_token_creates_and_reads_back(connect, issuer):
    async with connect(issuer.mint("alice", READ_WRITE)) as client:
        created = await client.call_tool("create_note", {"title": "plan", "body": "ship it"})
        note_id = created.structured_content["id"]

        fetched = await client.call_tool("get_note", {"note_id": note_id})
        assert fetched.structured_content["body"] == "ship it"

        found = await client.call_tool("search_notes", {"query": "PLAN"})
        assert [n["id"] for n in found.structured_content["result"]] == [note_id]


async def test_read_token_can_search_but_not_create(connect, issuer):
    async with connect(issuer.mint("alice", READ)) as client:
        found = await client.call_tool("search_notes", {"query": ""})
        assert not found.is_error

        with pytest.raises(MCPError) as exc:
            await client.call_tool("create_note", {"title": "x", "body": "y"})
        assert exc.value.code == INSUFFICIENT_SCOPE


async def test_another_users_note_reads_as_not_found(connect, issuer):
    async with connect(issuer.mint("alice", READ_WRITE)) as alice:
        created = await alice.call_tool("create_note", {"title": "private", "body": "alice only"})
        note_id = created.structured_content["id"]

    async with connect(issuer.mint("bob", READ_WRITE)) as bob:
        result = await bob.call_tool("get_note", {"note_id": note_id})
        assert result.is_error
        assert f"note {note_id} not found" in result.content[0].text

        found = await bob.call_tool("search_notes", {"query": "private"})
        assert found.structured_content["result"] == []


async def test_tools_declare_read_only_hints(connect, issuer):
    async with connect(issuer.mint("alice", READ)) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
    assert tools["search_notes"].annotations.read_only_hint is True
    assert tools["get_note"].annotations.read_only_hint is True
    assert tools["create_note"].annotations.read_only_hint is False


async def test_unknown_tool_is_refused(connect, issuer):
    async with connect(issuer.mint("alice", READ_WRITE)) as client:
        with pytest.raises(MCPError) as exc:
            await client.call_tool("drop_all_notes", {})
    assert exc.value.code == INVALID_PARAMS


async def test_tool_registered_without_a_scope_cannot_be_called(issuer, verifier):
    server = build_server(NoteStore(), verifier, issuer=ISSUER, resource_url=RESOURCE)

    @server.tool()
    def unscoped() -> str:
        return "reachable"

    app = server.streamable_http_app(host="testserver")
    async with (
        app.router.lifespan_context(app),
        open_client(app, issuer.mint(scopes=READ_WRITE)) as client,
    ):
        assert "unscoped" in [t.name for t in (await client.list_tools()).tools]
        with pytest.raises(MCPError) as exc:
            await client.call_tool("unscoped", {})
    assert exc.value.code == INVALID_PARAMS
