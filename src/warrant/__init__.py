"""warrant — a remote MCP server behind OAuth: verified tokens, per-tool scopes, per-user data."""

from warrant.auth import JwtVerifier
from warrant.server import build_app, build_server
from warrant.store import Note, NoteStore

__all__ = ["JwtVerifier", "Note", "NoteStore", "build_app", "build_server"]
__version__ = "0.0.1"
