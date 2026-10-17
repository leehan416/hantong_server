import asyncio
import hashlib
import secrets
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Optional

from app.auth.exceptions import CapacityExceededError, InvalidCredentialsError
from app.relay.exceptions import StreamActiveError
from app.relay.schemas import IssuedSession


class RelaySession:
    """Mutable per-token state. The raw token is never stored, only its SHA-256 digest."""

    def __init__(
        self,
        digest: str,
        subject: str,
        email: str,
        installation_id: str,
        expires_at: float,
    ) -> None:
        self.digest = digest
        self.subject = subject
        self.email = email
        self.installation_id = installation_id
        self.expires_at = expires_at
        # Holds only the latest history id; None tells the stream to stop.
        self.queue: asyncio.Queue[Optional[str]] = asyncio.Queue(maxsize=1)
        self.streaming = False
        self.revoked = False


class RelayService:
    """In-memory challenges, sessions and mailbox fan-out.

    ponytail: state lives in this process, so run one API process; move sessions and
    fan-out behind ports with a shared store before scaling out.
    """

    CHALLENGE_TTL_SECONDS = 300
    SESSION_TTL_SECONDS = 3600
    DEDUP_TTL_SECONDS = 600
    HEARTBEAT_SECONDS = 15
    MAX_CHALLENGES = 1000
    MAX_SESSIONS = 1000
    MAX_SESSIONS_PER_SUBJECT = 8
    MAX_DEDUP_ENTRIES = 10000

    def __init__(self, clock: Callable[[], float]) -> None:
        self.clock = clock
        self.challenges: dict[str, float] = {}
        self.sessions: dict[str, RelaySession] = {}
        self.by_installation: dict[tuple[str, str], str] = {}
        self.dedup: dict[str, float] = {}

    def create_challenge(self) -> str:
        self._clean()
        if len(self.challenges) >= self.MAX_CHALLENGES:
            raise CapacityExceededError
        nonce = secrets.token_urlsafe(32)
        self.challenges[digest_of(nonce)] = self.clock() + self.CHALLENGE_TTL_SECONDS
        return nonce

    def consume_challenge(self, nonce: str) -> bool:
        expires_at = self.challenges.pop(digest_of(nonce), None)
        if expires_at is None:
            return False
        return expires_at > self.clock()

    def create_session(
        self,
        subject: str,
        email: str,
        installation_id: str,
        token_expires_at: float,
    ) -> IssuedSession:
        """Issue a session; a new login from the same installation replaces the old one."""
        self._clean()
        installation = (subject, installation_id)
        prior = self.by_installation.get(installation)
        if prior:
            self._revoke_digest(prior)
        if len(self.by_installation) >= self.MAX_SESSIONS:
            raise CapacityExceededError
        if self._count_sessions(subject) >= self.MAX_SESSIONS_PER_SUBJECT:
            raise CapacityExceededError
        now = self.clock()
        expires_at = min(token_expires_at, now + self.SESSION_TTL_SECONDS)
        token = secrets.token_urlsafe(32)
        digest = digest_of(token)
        self.sessions[digest] = RelaySession(digest, subject, email, installation_id, expires_at)
        self.by_installation[installation] = digest
        return IssuedSession(access_token=token, expires_in=int(expires_at - now))

    def authenticate(self, token: str) -> RelaySession:
        self._clean()
        session = self.sessions.get(digest_of(token))
        if not session or session.revoked:
            raise InvalidCredentialsError
        return session

    def revoke(self, session: RelaySession) -> None:
        self._revoke_digest(session.digest)

    def close(self) -> None:
        for digest in list(self.sessions):
            self._revoke_digest(digest)

    def publish(self, message_id: str, email: str, history_id: str) -> bool:
        """Deliver to every session of the mailbox; Pub/Sub redeliveries are dropped."""
        self._clean()
        if message_id in self.dedup:
            return False
        if len(self.dedup) >= self.MAX_DEDUP_ENTRIES:
            del self.dedup[min(self.dedup, key=self.dedup.__getitem__)]
        self.dedup[message_id] = self.clock() + self.DEDUP_TTL_SECONDS
        mailbox = email.lower()
        for session in self.sessions.values():
            if session.email == mailbox:
                offer_latest(session.queue, history_id)
        return True

    def open_stream(self, session: RelaySession) -> None:
        if session.streaming:
            raise StreamActiveError
        session.streaming = True

    def release_stream(self, session: RelaySession) -> None:
        session.streaming = False

    async def events(
        self,
        session: RelaySession,
        is_disconnected: Callable[[], Awaitable[bool]],
    ) -> AsyncIterator[Optional[str]]:
        """Yield history ids as they arrive and None as a heartbeat.

        Ends when the client disconnects or the session is revoked or expires.
        """
        try:
            while not await is_disconnected():
                if not self._live(session):
                    return
                timeout = min(self.HEARTBEAT_SECONDS, max(0.01, session.expires_at - self.clock()))
                try:
                    history_id = await asyncio.wait_for(session.queue.get(), timeout)
                except TimeoutError:
                    if not self._live(session):
                        return
                    yield None
                    continue
                if not history_id or not self._live(session):
                    return
                yield history_id
        finally:
            self.release_stream(session)

    def _live(self, session: RelaySession) -> bool:
        return not session.revoked and session.expires_at > self.clock()

    def _count_sessions(self, subject: str) -> int:
        count = 0
        for session in self.sessions.values():
            if session.subject == subject:
                count += 1
        return count

    def _clean(self) -> None:
        now = self.clock()
        drop_expired(self.challenges, now)
        drop_expired(self.dedup, now)
        for digest, session in list(self.sessions.items()):
            if session.expires_at <= now:
                self._revoke_digest(digest)

    def _revoke_digest(self, digest: str) -> None:
        session = self.sessions.pop(digest, None)
        if not session:
            return
        session.revoked = True
        self.by_installation.pop((session.subject, session.installation_id), None)
        offer_latest(session.queue, None)


def digest_of(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def drop_expired(entries: dict[str, float], now: float) -> None:
    for key, expires_at in list(entries.items()):
        if expires_at <= now:
            del entries[key]


def offer_latest(queue: "asyncio.Queue[Optional[str]]", value: Optional[str]) -> None:
    if queue.full():
        queue.get_nowait()
    queue.put_nowait(value)
