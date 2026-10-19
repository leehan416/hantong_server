import hmac
from collections.abc import Callable

from app.auth.exceptions import InvalidCredentialsError
from app.auth.ports import IdentityTokenVerifier
from app.auth.schemas import ChallengeData, IdentityClaims, SessionInput
from app.core.settings import Settings
from app.relay.schemas import IssuedSession
from app.relay.service import RelayService

GOOGLE_ISSUERS = {"accounts.google.com", "https://accounts.google.com"}
CONSUMER_DOMAINS = {"gmail.com", "googlemail.com"}
MAX_TOKEN_LIFETIME_SECONDS = 3660
MAX_CLOCK_SKEW_SECONDS = 60
MAX_TOKEN_AGE_SECONDS = 3600
MIN_SESSION_SECONDS = 1


class AuthService:
    def __init__(
        self,
        settings: Settings,
        relay: RelayService,
        verifier: IdentityTokenVerifier,
        clock: Callable[[], float],
    ) -> None:
        self.settings = settings
        self.relay = relay
        self.verifier = verifier
        self.clock = clock

    def create_challenge(self) -> ChallengeData:
        nonce = self.relay.create_challenge()
        return ChallengeData(nonce=nonce, expires_in=self.relay.CHALLENGE_TTL_SECONDS)

    async def create_session(self, data: SessionInput) -> IssuedSession:
        if not self.relay.consume_challenge(data.nonce):
            raise InvalidCredentialsError
        audience = str(self.settings.GOOGLE_CLIENT_ID)
        claims = await self.verifier.verify(data.id_token, audience)
        now = self.clock()
        if not claims_valid(claims, audience, now):
            raise InvalidCredentialsError
        if not nonce_matches(claims, data.nonce):
            raise InvalidCredentialsError
        if not mailbox_identity_valid(claims):
            raise InvalidCredentialsError
        if claims.exp < now + MIN_SESSION_SECONDS:
            raise InvalidCredentialsError
        return self.relay.create_session(
            claims.sub,
            str(claims.email).lower(),
            data.installation_id,
            claims.exp,
        )

    async def verify_push_token(self, token: str) -> None:
        audience = str(self.settings.PUBSUB_AUDIENCE)
        claims = await self.verifier.verify(token, audience)
        if not claims_valid(claims, audience, self.clock()):
            raise InvalidCredentialsError
        if (
            not claims.email
            or claims.email.lower() != str(self.settings.PUBSUB_SERVICE_ACCOUNT_EMAIL).lower()
        ):
            raise InvalidCredentialsError


def claims_valid(claims: IdentityClaims, audience: str, now: float) -> bool:
    if claims.iss not in GOOGLE_ISSUERS:
        return False
    if not audience_matches(claims.aud, audience):
        return False
    if claims.exp <= now or claims.exp > now + MAX_TOKEN_LIFETIME_SECONDS:
        return False
    if claims.iat > now + MAX_CLOCK_SKEW_SECONDS or claims.iat < now - MAX_TOKEN_AGE_SECONDS:
        return False
    if claims.email_verified is not True:
        return False
    return bool(claims.sub.strip())


def audience_matches(token_audience: str | list[str], audience: str) -> bool:
    if isinstance(token_audience, list):
        return audience in token_audience
    return token_audience == audience


def nonce_matches(claims: IdentityClaims, nonce: str) -> bool:
    if not claims.nonce:
        return False
    return hmac.compare_digest(claims.nonce.encode(), nonce.encode())


def mailbox_identity_valid(claims: IdentityClaims) -> bool:
    """Accept consumer Gmail accounts and Workspace accounts whose hd matches the domain."""
    if not claims.email or "@" not in claims.email:
        return False
    domain = claims.email.rsplit("@", 1)[1].lower()
    if domain in CONSUMER_DOMAINS:
        return True
    if not claims.hd:
        return False
    return claims.hd.lower() == domain
