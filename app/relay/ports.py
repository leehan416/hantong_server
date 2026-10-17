from abc import ABC, abstractmethod
from typing import NamedTuple


class StoredGrant(NamedTuple):
    digest: str
    subject: str
    email: str
    installation_id: str
    expires_at: float


class StoredSpent(NamedTuple):
    digest: str
    subject: str
    installation_id: str
    expires_at: float


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
    def delete(self, digest: str) -> None:
        """Remove the digest from both live grants and spent records."""
        pass

    @abstractmethod
    def delete_expired(self, now: float) -> None:
        pass
