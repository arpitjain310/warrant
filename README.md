# warrant

[![ci](https://github.com/arpitjain310/warrant/actions/workflows/ci.yml/badge.svg)](https://github.com/arpitjain310/warrant/actions/workflows/ci.yml)

> A remote MCP server that acts as a proper OAuth resource server: every tool
> call is authenticated against an external identity provider, authorized per
> tool, and scoped to the caller's own data.

**Status:** work in progress.

---

## The problem

Most MCP server examples run over stdio and trust whoever launched them. On a
URL, every request comes from a client you don't control, carrying a token
issued by an authorization server you don't run. Each request has to answer:

- **Is the token genuine?** Signature against the issuer's published keys,
  issuer, expiry.
- **Was it issued for this server?** A token minted for a different API is
  refused (audience). Otherwise any service that sees a user's token can replay
  it here.
- **Can it call this tool?** Read and write are separate scopes; a read-only
  token can't create.
- **Whose data?** Every query is filtered by the token's subject. There is no
  unscoped read path.

The server never issues tokens. Login, consent and client registration stay with
the authorization server; this side only verifies.

## What it does

```
client ── POST /mcp + Bearer ──▶ JwtVerifier ──▶ scope gate ──▶ tool ──▶ NoteStore
  ▲                              JWKS, iss,      tool → scope   owner =    SQLite
  │                              aud, exp                       token.sub
  └── 401 + resource_metadata ◀── missing / invalid token
      (client discovers the authorization server and logs the user in)
```

- **Discovery** — an unauthenticated request gets `401` with
  `WWW-Authenticate: Bearer resource_metadata=...`. The protected resource
  metadata (RFC 9728) names the authorization server and every tool scope, so a
  client can run the login without per-server configuration.
- **JwtVerifier** (`auth.py`) — validates JWT access tokens (RFC 9068) against
  the issuer's JWKS: signature, `iss`, `aud`, `exp`, `sub`. RS256 only. An
  unknown key ID triggers one JWKS refetch (key rotation), with a cooldown so
  forged key IDs can't make it hammer the issuer.
- **Scope gate** (`server.py`) — each tool is registered with the scope it
  needs, and the gate checks it before the tool runs. It fails closed: a tool
  registered without a scope can't be called.
- **NoteStore** (`store.py`) — SQLite. Every method takes the owner.

## Tools

| Tool | Scope | Notes |
|------|-------|-------|
| `search_notes(query, limit)` | `notes:read` | Case-insensitive substring; empty query lists the most recent. |
| `get_note(note_id)` | `notes:read` | Another user's note reads as not found. |
| `create_note(title, body)` | `notes:write` | |

## Explicit non-goals

- Not an authorization server — no login, token issuance or client
  registration. Targets any OIDC provider that issues JWT access tokens.
- Not a gateway — one server, its own tools.
- Notes are a deliberately small domain; the auth layer is the point.

## Protocol

Built on the official Python SDK (`mcp` 2.x) at MCP revision 2026-07-28:
stateless, no sessions, each request carries its own protocol version. The SDK
handles transport and the `401`. Token verification, per-tool scopes, the
metadata's scope list and per-user data scoping are here.

## Quickstart

```bash
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -q
```

Run it against an identity provider. The API (audience) identifier is the
server's public `/mcp` URL, with `notes:read` and `notes:write` defined as its
scopes:

```bash
warrant --issuer https://YOUR_TENANT/ --resource-url http://localhost:8000/mcp
```
