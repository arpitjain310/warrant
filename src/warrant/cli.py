"""warrant — run the server."""

from __future__ import annotations

import argparse
import os

import uvicorn

from warrant.auth import JwtVerifier, discover_jwks_url
from warrant.dev import DevIssuer
from warrant.server import READ, WRITE, build_app
from warrant.store import NoteStore


def main(argv: list[str] | None = None) -> None:
    env = os.environ.get
    p = argparse.ArgumentParser(prog="warrant", description="Notes MCP server behind OAuth.")
    p.add_argument(
        "--issuer", default=env("WARRANT_ISSUER"), help="authorization server issuer URL"
    )
    p.add_argument(
        "--resource-url",
        default=env("WARRANT_RESOURCE_URL"),
        help="public URL of this server's /mcp endpoint",
    )
    p.add_argument("--audience", default=env("WARRANT_AUDIENCE"), help="default: --resource-url")
    p.add_argument("--jwks-url", default=env("WARRANT_JWKS_URL"), help="default: OIDC discovery")
    p.add_argument("--db", default=env("WARRANT_DB", "warrant.db"))
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument(
        "--dev",
        action="store_true",
        help="no identity provider: run a local issuer and print tokens",
    )
    args = p.parse_args(argv)

    if args.dev:
        resource_url = args.resource_url or f"http://{args.host}:{args.port}/mcp"
        dev = DevIssuer(audience=resource_url)
        issuer, audience, jwks_url = dev.issuer, resource_url, dev.jwks_url
        print(f"dev issuer {issuer} (tokens valid 1h, user 'dev')")
        print(f"  read:       {dev.mint(scopes=(READ,))}")
        print(f"  read+write: {dev.mint(scopes=(READ, WRITE))}", flush=True)
    elif args.issuer and args.resource_url:
        resource_url, issuer = args.resource_url, args.issuer
        audience = args.audience or resource_url
        jwks_url = args.jwks_url or discover_jwks_url(issuer)
    else:
        p.error(
            "--issuer and --resource-url are required (or WARRANT_ISSUER / WARRANT_RESOURCE_URL),"
            " or use --dev"
        )

    app = build_app(
        NoteStore(args.db),
        JwtVerifier(issuer=issuer, audience=audience, jwks_url=jwks_url),
        issuer=issuer,
        resource_url=resource_url,
        host=args.host,
    )
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
