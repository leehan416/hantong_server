import asyncio
import threading
import time
from collections.abc import Mapping
from typing import Any, Optional

from pydantic import ValidationError
from typing_extensions import override

from app.auth.exceptions import IdentityVerifierUnavailableError, InvalidCredentialsError
from app.auth.ports import IdentityTokenVerifier
from app.auth.schemas import IdentityClaims

CERTS_URL = "https://www.googleapis.com/oauth2/v1/certs"
CERT_CACHE_SECONDS = 300
MAX_CERT_BYTES = 262144
REQUEST_TIMEOUT_SECONDS = 5


class CachedResponse:
    def __init__(self, status: int, headers: dict[str, str], data: bytes) -> None:
        self.status = status
        self.headers = headers
        self.data = data


class CertificateCache:
    """Caches only Google's public certificate response, never anything token specific."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.response: Optional[CachedResponse] = None
        self.stored_at = 0.0

    def get(self, now: float) -> Optional[CachedResponse]:
        with self.lock:
            if now - self.stored_at >= CERT_CACHE_SECONDS:
                return None
            return self.response

    def put(self, response: Any, now: float) -> None:
        data = getattr(response, "data", None)
        if data is None or len(data) > MAX_CERT_BYTES:
            return
        with self.lock:
            self.response = CachedResponse(response.status, dict(response.headers), data)
            self.stored_at = now


class CachedBoundedRequest:
    """google-auth transport wrapper: bounded timeout and cached certificate fetches."""

    def __init__(self, request: Any, cache: CertificateCache) -> None:
        self.request = request
        self.cache = cache

    def __call__(
        self,
        url: str,
        method: str = "GET",
        body: Any = None,
        headers: Any = None,
        timeout: Any = None,
        **kwargs: Any,
    ) -> Any:
        is_cert_fetch = url == CERTS_URL and method == "GET" and body is None
        if is_cert_fetch:
            cached = self.cache.get(time.monotonic())
            if cached:
                return cached
        response = self.request(
            url,
            method=method,
            body=body,
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
            **kwargs,
        )
        if is_cert_fetch and response.status == 200:
            self.cache.put(response, time.monotonic())
        return response


def verify_google_token(token: str, audience: str, cache: CertificateCache) -> Mapping[str, Any]:
    try:
        from google.auth import exceptions as google_auth_exceptions
        from google.auth.transport.requests import Request
        from google.oauth2 import id_token
    except ImportError:
        raise IdentityVerifierUnavailableError from None
    try:
        request = CachedBoundedRequest(Request(), cache)
        return id_token.verify_oauth2_token(token, request, audience=audience)
    except (
        google_auth_exceptions.TransportError,
        google_auth_exceptions.TimeoutError,
        google_auth_exceptions.ResponseError,
    ):
        raise IdentityVerifierUnavailableError from None
    except Exception:
        raise InvalidCredentialsError from None


class GoogleIdentityTokenVerifier(IdentityTokenVerifier):
    """Runs the blocking google-auth check in threads, at most max_concurrency at once."""

    def __init__(self, max_concurrency: int = 4) -> None:
        self.max_concurrency = max_concurrency
        self.active = 0
        self.cache = CertificateCache()

    @override
    async def verify(self, token: str, audience: str) -> IdentityClaims:
        payload = await self._verify_bounded(token, audience)
        try:
            return IdentityClaims.model_validate(payload)
        except ValidationError:
            raise InvalidCredentialsError from None

    def verify_token(self, token: str, audience: str) -> Mapping[str, Any]:
        return verify_google_token(token, audience, self.cache)

    async def _verify_bounded(self, token: str, audience: str) -> Mapping[str, Any]:
        if self.active >= self.max_concurrency:
            raise IdentityVerifierUnavailableError
        self.active += 1
        worker = asyncio.create_task(asyncio.to_thread(self.verify_token, token, audience))
        worker.add_done_callback(self._release)
        try:
            # A cancelled request keeps its slot until the thread really finishes.
            return await asyncio.shield(worker)
        except IdentityVerifierUnavailableError:
            raise
        except Exception:
            raise InvalidCredentialsError from None

    def _release(self, worker: "asyncio.Task[Mapping[str, Any]]") -> None:
        self.active -= 1
        if not worker.cancelled():
            worker.exception()
