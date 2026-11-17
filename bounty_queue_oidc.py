"""Verify GitHub Actions OIDC tokens for read-only discovery ingestion.

No shared secret or user-supplied token configuration is required.
Accepts only the canonical workflow running on the default branch.
"""
import os

AUDIENCE = "garcar-bounty-queue-staging"
ISSUER = "https://token.actions.githubusercontent.com"
REPOSITORY = "Garrettc123/ai-swarm-crypto-bounty-system"
REPOSITORY_ID = "1088230416"
WORKFLOW_REF = (
    "Garrettc123/ai-swarm-crypto-bounty-system/"
    ".github/workflows/bounty-scan.yml@refs/heads/main"
)
EVENTS = frozenset({"push", "schedule", "workflow_dispatch"})


def verify_actions_token(token):
    if not isinstance(token, str) or not 100 < len(token) < 12000:
        raise PermissionError("invalid identity token")
    try:
        import jwt
        # PyJWKClient verifies signatures against GitHub's TLS-served JWK set;
        # never parse unsigned claims to grant access.
        jwks = jwt.PyJWKClient(ISSUER + "/.well-known/jwks")
        key = jwks.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token, key=key, algorithms=["RS256"], audience=AUDIENCE,
            issuer=ISSUER, leeway=30,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
    except Exception as exc:
        raise PermissionError("GitHub identity verification failed") from exc
    if (str(claims.get("repository_id")) != REPOSITORY_ID
            or claims.get("repository") != REPOSITORY
            or claims.get("ref") != "refs/heads/main"
            or claims.get("workflow_ref") != WORKFLOW_REF
            or claims.get("event_name") not in EVENTS):
        raise PermissionError("GitHub workflow identity is not authorized")
    return {"repository": REPOSITORY, "event_name": claims["event_name"]}
