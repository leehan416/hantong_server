from typing import Any

from pydantic import ValidationError
from typing_extensions import override

from app.auth.exceptions import IdentityVerifierUnavailableError, InvalidCredentialsError
from app.auth.ports import IdentityTokenVerifier
from app.auth.schemas import IdentityClaims
from app.core.settings import Settings

SETTINGS = Settings(
    GOOGLE_CLIENT_ID="client",
    PUBSUB_AUDIENCE="https://push.example",
    PUBSUB_SERVICE_ACCOUNT_EMAIL="push@project.iam.gserviceaccount.com",
    PUBSUB_SUBSCRIPTION="projects/p/subscriptions/s",
)
NOW = 1000.0
INSTALLATION_ID = "123e4567-e89b-42d3-a456-426614174000"


class FakeIdentityTokenVerifier(IdentityTokenVerifier):
    """Accepts exactly the tokens registered in `tokens`."""

    def __init__(self) -> None:
        self.tokens: dict[str, dict[str, Any]] = {}
        self.unavailable = False

    @override
    async def verify(self, token: str, audience: str) -> IdentityClaims:
        if self.unavailable:
            raise IdentityVerifierUnavailableError
        if token not in self.tokens:
            raise InvalidCredentialsError
        try:
            return IdentityClaims.model_validate(self.tokens[token])
        except ValidationError:
            raise InvalidCredentialsError from None


def user_claims(nonce: str, **overrides: Any) -> dict[str, Any]:
    claims = {
        "aud": "client",
        "iss": "https://accounts.google.com",
        "exp": 2000,
        "iat": 999,
        "email": "a@gmail.com",
        "email_verified": True,
        "sub": "s",
        "nonce": nonce,
    }
    claims.update(overrides)
    return claims


def push_claims(**overrides: Any) -> dict[str, Any]:
    claims = {
        "aud": SETTINGS.PUBSUB_AUDIENCE,
        "iss": "https://accounts.google.com",
        "exp": 2000,
        "iat": 999,
        "email": SETTINGS.PUBSUB_SERVICE_ACCOUNT_EMAIL,
        "email_verified": True,
        "sub": "push",
    }
    claims.update(overrides)
    return claims
