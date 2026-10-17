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


class RefreshGrant:
    """A single-use refresh credential for one Google sub × installation; stored by digest."""

    def __init__(self, subject: str, email: str, installation_id: str, expires_at: float) -> None:
        self.subject = subject
        self.email = email
        self.installation_id = installation_id
        self.expires_at = expires_at


class RelayService:
    """In-memory challenges, sessions and mailbox fan-out.

    ponytail: state lives in this process, so run one API process; move sessions and
    fan-out behind ports with a shared store before scaling out.
    """

    CHALLENGE_TTL_SECONDS = 300
    SESSION_TTL_SECONDS = 3600
    REFRESH_TTL_SECONDS = 30 * 86400
    DEDUP_TTL_SECONDS = 600
    HEARTBEAT_SECONDS = 15
    MAX_CHALLENGES = 1000
    MAX_SESSIONS = 1000
    MAX_SESSIONS_PER_SUBJECT = 8
    MAX_DEDUP_ENTRIES = 10000
    MAX_REFRESH_GRANTS = 10000

    def __init__(self, clock: Callable[[], float]) -> None:
        self.clock = clock
        self.challenges: dict[str, float] = {}
        self.sessions: dict[str, RelaySession] = {}
        self.by_installation: dict[tuple[str, str], str] = {}
        self.dedup: dict[str, float] = {}
        self.refresh_grants: dict[str, RefreshGrant] = {}
        self.refresh_by_installation: dict[tuple[str, str], str] = {}
        # Rotated-out refresh digests, kept until they would have expired, to detect replay.
        self.spent_refresh: dict[str, tuple[tuple[str, str], float]] = {}

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
        return self._issue(
            subject,
            email,
            installation_id,
            min(token_expires_at, self.clock() + self.SESSION_TTL_SECONDS),
        )

    def refresh(self, refresh_token: str) -> IssuedSession:
        """Rotate a refresh credential into a new session; a replayed spent one revokes it all."""
        self._clean()
        digest = digest_of(refresh_token)
        spent = self.spent_refresh.get(digest)
        if spent:
            self._revoke_installation(spent[0])
            raise InvalidCredentialsError
        grant = self.refresh_grants.get(digest)
        if not grant:
            raise InvalidCredentialsError
        installation = (grant.subject, grant.installation_id)
        self._drop_refresh(installation)
        return self._issue(
            grant.subject,
            grant.email,
            grant.installation_id,
            self.clock() + self.SESSION_TTL_SECONDS,
        )

    def _issue(
        self,
        subject: str,
        email: str,
        installation_id: str,
        expires_at: float,
    ) -> IssuedSession:
        installation = (subject, installation_id)
        prior = self.by_installation.get(installation)
        if prior:
            self._revoke_digest(prior)
        if len(self.by_installation) >= self.MAX_SESSIONS:
            raise CapacityExceededError
        if self._count_sessions(subject) >= self.MAX_SESSIONS_PER_SUBJECT:
            raise CapacityExceededError
        # A fresh Google login supersedes the old credential; its later use is not treated as theft.
        old_refresh = self.refresh_by_installation.pop(installation, None)
        if old_refresh:
            self.refresh_grants.pop(old_refresh, None)
        if len(self.refresh_grants) >= self.MAX_REFRESH_GRANTS:
            raise CapacityExceededError
        now = self.clock()
        token = secrets.token_urlsafe(32)
        digest = digest_of(token)
        self.sessions[digest] = RelaySession(digest, subject, email, installation_id, expires_at)
        self.by_installation[installation] = digest
        refresh_token = secrets.token_urlsafe(32)
        refresh_digest = digest_of(refresh_token)
        self.refresh_grants[refresh_digest] = RefreshGrant(
            subject, email, installation_id, now + self.REFRESH_TTL_SECONDS
        )
        self.refresh_by_installation[installation] = refresh_digest
        return IssuedSession(
            access_token=token, expires_in=int(expires_at - now), refresh_token=refresh_token
        )

    def authenticate(self, token: str) -> RelaySession:
        self._clean()
        session = self.sessions.get(digest_of(token))
        if not session or session.revoked:
            raise InvalidCredentialsError
        return session

    def revoke(self, session: RelaySession) -> None:
        """Logout: end the session and its refresh credential; the next login needs Google."""
        self._revoke_installation((session.subject, session.installation_id))
        self._revoke_digest(session.digest)

    def close(self) -> None:
        for digest in list(self.sessions):
            self._revoke_digest(digest)
        self.refresh_grants.clear()
        self.refresh_by_installation.clear()
        self.spent_refresh.clear()

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
        for digest, (_, expires_at) in list(self.spent_refresh.items()):
            if expires_at <= now:
                del self.spent_refresh[digest]
        for digest, grant in list(self.refresh_grants.items()):
            if grant.expires_at <= now:
                self.refresh_grants.pop(digest)
                self.refresh_by_installation.pop((grant.subject, grant.installation_id), None)
        for digest, session in list(self.sessions.items()):
            if session.expires_at <= now:
                self._revoke_digest(digest)

    def _drop_refresh(self, installation: tuple[str, str]) -> None:
        """Retire the installation's live refresh digest, remembering it so a replay is caught."""
        digest = self.refresh_by_installation.pop(installation, None)
        if not digest:
            return
        grant = self.refresh_grants.pop(digest, None)
        if not grant:
            return
        if len(self.spent_refresh) >= self.MAX_REFRESH_GRANTS:
            del self.spent_refresh[
                min(self.spent_refresh, key=lambda key: self.spent_refresh[key][1])
            ]
        self.spent_refresh[digest] = (installation, grant.expires_at)

    def _revoke_installation(self, installation: tuple[str, str]) -> None:
        self._drop_refresh(installation)
        session_digest = self.by_installation.get(installation)
        if session_digest:
            self._revoke_digest(session_digest)

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
