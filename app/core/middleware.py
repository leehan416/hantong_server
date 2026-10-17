import asyncio

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.api.exception.codes import ErrorCode
from app.api.exception.handlers import error_response


class BodyGuard:
    """Bound request bodies before FastAPI parses them."""

    def __init__(self, app: ASGIApp, limit: int = 32768, timeout_seconds: float = 5) -> None:
        self.app = app
        self.limit = limit
        self.timeout_seconds = timeout_seconds

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return
        if self._declared_too_large(scope):
            await self._reject(
                ErrorCode.PAYLOAD_TOO_LARGE, "Request too large", scope, receive, send
            )
            return
        try:
            async with asyncio.timeout(self.timeout_seconds):
                body = await self._read_body(receive)
        except TimeoutError:
            await self._reject(ErrorCode.REQUEST_TIMEOUT, "Request timeout", scope, receive, send)
            return
        except OverflowError:
            await self._reject(
                ErrorCode.PAYLOAD_TOO_LARGE, "Request too large", scope, receive, send
            )
            return
        if body is None:
            return
        await self.app(scope, replay(body, receive), send)

    def _declared_too_large(self, scope: Scope) -> bool:
        for name, value in scope.get("headers", []):
            if name != b"content-length":
                continue
            try:
                return int(value) > self.limit
            except ValueError:
                return True
        return False

    async def _read_body(self, receive: Receive) -> bytes | None:
        chunks = []
        size = 0
        while True:
            event = await receive()
            if event["type"] == "http.disconnect":
                return None
            chunk = event.get("body", b"")
            size += len(chunk)
            if size > self.limit:
                raise OverflowError
            chunks.append(chunk)
            if not event.get("more_body", False):
                return b"".join(chunks)

    async def _reject(
        self, code: ErrorCode, message: str, scope: Scope, receive: Receive, send: Send
    ) -> None:
        response = error_response(code, message)
        await response(scope, receive, send)


def replay(body: bytes, receive: Receive) -> Receive:
    sent = False

    async def receive_replayed() -> Message:
        nonlocal sent
        if sent:
            return await receive()
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return receive_replayed
