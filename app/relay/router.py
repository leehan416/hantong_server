import json
from collections.abc import AsyncIterator
from typing import Optional

from fastapi import APIRouter, Depends, Request

from app.api.deps import limit_stream_requests
from app.core.responses import CleanupStreamingResponse
from app.relay.dependencies import CurrentSessionDep, RelayServiceDep

router = APIRouter(prefix="/events", tags=["relay"])

READY_EVENT = 'event: ready\ndata: {"resync":true}\n\n'
HEARTBEAT = ": heartbeat\n\n"


@router.get("", dependencies=[Depends(limit_stream_requests)])
async def stream_events_api(
    request: Request,
    session: CurrentSessionDep,
    relay: RelayServiceDep,
) -> CleanupStreamingResponse:
    relay.open_stream(session)
    return CleanupStreamingResponse(
        sse_stream(relay.events(session, request.is_disconnected)),
        cleanup=lambda: relay.release_stream(session),
        media_type="text/event-stream",
        headers={"cache-control": "no-cache", "x-accel-buffering": "no"},
    )


async def sse_stream(history_ids: AsyncIterator[Optional[str]]) -> AsyncIterator[str]:
    # Clients resync on connect, then only hear the latest history id per change.
    yield READY_EVENT
    async for history_id in history_ids:
        if not history_id:
            yield HEARTBEAT
            continue
        payload = json.dumps({"historyId": history_id}, separators=(",", ":"))
        yield "event: mailbox_changed\ndata: " + payload + "\n\n"
