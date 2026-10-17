from collections.abc import Callable
from typing import Any

from fastapi.responses import StreamingResponse
from starlette.types import Receive, Scope, Send


class CleanupStreamingResponse(StreamingResponse):
    """Runs cleanup even when the response fails before its generator starts."""

    def __init__(self, *args: Any, cleanup: Callable[[], None], **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.cleanup = cleanup

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            self.cleanup()
