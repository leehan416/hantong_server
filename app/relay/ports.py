from abc import ABC, abstractmethod
from typing import NamedTuple, Optional


class StoredGrant(NamedTuple):
    digest: str
    subject: str
    email: str
    installation_id: str
    expires_at: float
    generation_id: Optional[str] = None


class StoredSpent(NamedTuple):
    digest: str
    subject: str
    installation_id: str
    expires_at: float
    generation_id: Optional[str] = None


class RefreshStore(ABC):
    """Durable copy of refresh grants so a server restart does not force every client to re-login.

    Only SHA-256 digests are stored, never raw tokens. The relay keeps its in-memory view as the
    source of truth while running and writes every change through.
    """

    @abstractmethod
    def load(self) -> tuple[list[StoredGrant], list[StoredSpent]]:
        pass

    @abstractmethod
    def put_grant(self, grant: StoredGrant) -> None:
        pass

    @abstractmethod
    def put_spent(self, spent: StoredSpent) -> None:
        pass

    @abstractmethod
    def rotate(
        self,
        old_digest: str,
        spent: StoredSpent,
        grant: StoredGrant,
        evict_spent_digest: Optional[str] = None,
    ) -> None:
        """Atomically replace a live refresh grant with its spent marker and successor."""
        pass

    @abstractmethod
    def replace_grant(
        self, old_digest: str, grant: StoredGrant, subject: str, installation_id: str
    ) -> None:
        """Replace a login grant and clear replay markers for the prior installation generation."""
        pass

    @abstractmethod
    def revoke_installation(
        self, old_digest: Optional[str], subject: str, installation_id: str
    ) -> None:
        """Remove refresh state for a logged-out installation."""
        pass

    @abstractmethod
    def delete(self, digest: str) -> None:
        """Remove the digest from both live grants and spent records."""
        pass

    @abstractmethod
    def delete_expired(self, now: float) -> None:
        pass
