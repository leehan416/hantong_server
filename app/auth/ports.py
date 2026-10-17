from abc import ABC, abstractmethod

from app.auth.schemas import IdentityClaims


class IdentityTokenVerifier(ABC):
    @abstractmethod
    async def verify(self, token: str, audience: str) -> IdentityClaims:
        """Check the token signature for audience and return its claims.

        Raises InvalidCredentialsError for a rejected token and
        IdentityVerifierUnavailableError when verification cannot run.
        """
        pass
