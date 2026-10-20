"""Access-token verification against an external OAuth authorization server."""

from __future__ import annotations

import json
import logging
import urllib.request

import anyio.to_thread
import jwt
from mcp.server.auth.provider import AccessToken

log = logging.getLogger(__name__)


class JwtVerifier:
    """Validates JWT access tokens (RFC 9068) against the issuer's JWKS.

    Implements the SDK's TokenVerifier. Any failure returns None, which the SDK
    answers with 401. Audience is checked here, so the SDK's resource check is
    left off.
    """

    def __init__(
        self,
        issuer: str,
        audience: str,
        jwks_url: str,
        *,
        leeway: int = 30,
        jwks_cooldown: float = 30,
    ):
        self.issuer = issuer
        self.audience = audience
        # Leeway covers clock skew on iat/nbf; the SDK re-checks exp without it.
        self.leeway = leeway
        # Refetches once on an unknown kid (rotation). The cooldown stops forged
        # kids from turning every bad request into a call to the issuer.
        self._jwks = jwt.PyJWKClient(jwks_url, cooldown_duration=jwks_cooldown)

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            # Blocking HTTP on a cache miss.
            key = await anyio.to_thread.run_sync(self._jwks.get_signing_key_from_jwt, token)
            claims = jwt.decode(
                token,
                key.key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway,
                options={"require": ["exp", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError as exc:
            log.info("token rejected: %s", exc)
            return None

        return AccessToken(
            token=token,
            client_id=claims.get("client_id") or claims.get("azp") or "",
            scopes=str(claims.get("scope", "")).split(),
            expires_at=int(claims["exp"]),
            resource=self.audience,
            subject=claims["sub"],
            claims={"iss": claims["iss"]},
        )


def discover_jwks_url(issuer: str) -> str:
    """Read jwks_uri from the issuer's OpenID configuration."""
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.load(resp)["jwks_uri"]
