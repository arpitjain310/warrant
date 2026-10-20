import time

import jwt
import pytest

from warrant.auth import JwtVerifier

from .conftest import ISSUER, RESOURCE, new_key

pytestmark = pytest.mark.anyio


async def test_valid_token_maps_subject_scopes_and_client(issuer, verifier):
    token = issuer.mint("alice", ("notes:read", "notes:write"))
    access = await verifier.verify_token(token)
    assert access.subject == "alice"
    assert access.scopes == ["notes:read", "notes:write"]
    assert access.client_id == "test-client"
    assert access.resource == RESOURCE


async def test_rejects_token_for_another_audience(issuer, verifier):
    # Same issuer, same user, minted for a different API: must not replay here.
    assert await verifier.verify_token(issuer.mint(aud="https://other-api.test/")) is None


async def test_accepts_audience_list_containing_this_server(issuer, verifier):
    token = issuer.mint(aud=[RESOURCE, ISSUER + "userinfo"])
    assert (await verifier.verify_token(token)).subject == "alice"


async def test_rejects_wrong_issuer(issuer, verifier):
    assert await verifier.verify_token(issuer.mint(iss="https://evil.test/")) is None


async def test_rejects_expired_token(issuer, verifier):
    assert await verifier.verify_token(issuer.mint(ttl=-120)) is None


async def test_rejects_token_without_subject(issuer, verifier):
    kid, key = issuer.keys[0]
    now = int(time.time())
    payload = {"iss": ISSUER, "aud": RESOURCE, "iat": now, "exp": now + 300, "scope": "notes:read"}
    token = jwt.encode(payload, key, algorithm="RS256", headers={"kid": kid})
    assert await verifier.verify_token(token) is None


async def test_rejects_forged_signature_under_a_real_kid(issuer, verifier):
    real_kid = issuer.keys[0][0]
    _, attacker_key = new_key()
    assert await verifier.verify_token(issuer.mint(key=(real_kid, attacker_key))) is None


async def test_rejects_hs256_signed_with_the_public_key(issuer, verifier):
    # Algorithm confusion: an HMAC token keyed with the published RSA key.
    kid = issuer.keys[0][0]
    public_jwk = issuer.jwks()["keys"][0]
    now = int(time.time())
    payload = {"iss": ISSUER, "aud": RESOURCE, "sub": "alice", "iat": now, "exp": now + 300}
    token = jwt.encode(payload, public_jwk["n"], algorithm="HS256", headers={"kid": kid})
    assert await verifier.verify_token(token) is None


async def test_rotated_key_accepted_after_one_refetch(issuer):
    verifier = JwtVerifier(ISSUER, RESOURCE, issuer.jwks_url, jwks_cooldown=0)
    assert await verifier.verify_token(issuer.mint()) is not None
    assert issuer.fetches == 1

    issuer.rotate()
    assert await verifier.verify_token(issuer.mint()) is not None
    assert issuer.fetches == 2


async def test_unknown_kid_does_not_refetch_during_cooldown(issuer, verifier):
    assert await verifier.verify_token(issuer.mint()) is not None
    assert issuer.fetches == 1

    for _ in range(5):
        assert await verifier.verify_token(issuer.mint(key=new_key())) is None
    assert issuer.fetches == 1
