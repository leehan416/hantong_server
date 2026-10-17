import asyncio
import json
from urllib.parse import urlsplit


async def request(
    app,
    method,
    path,
    *,
    headers=None,
    body=b"",
    disconnect_after=None,
    fail_on_start=False,
    started_event=None,
    capture=None,
):
    parsed = urlsplit(path)
    sent = []
    delivered = False

    async def receive():
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        await asyncio.sleep(3600)
        return {"type": "http.disconnect"}

    async def send(message):
        if fail_on_start and message.get("type") == "http.response.start":
            raise RuntimeError("send failed")
        sent.append(message)
        if capture is not None:
            capture.append(message)
        if started_event is not None and message.get("type") == "http.response.body":
            started_event.set()
        if disconnect_after is not None and message.get("type") == "http.response.body":
            bodies = [m for m in sent if m.get("type") == "http.response.body"]
            if len(bodies) >= disconnect_after:
                raise asyncio.CancelledError

    hs = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": parsed.path,
        "raw_path": parsed.path.encode(),
        "query_string": parsed.query.encode(),
        "root_path": "",
        "headers": hs,
        "client": ("127.0.0.1", 1234),
        "server": ("test", 80),
    }
    try:
        await app(scope, receive, send)
    except asyncio.CancelledError:
        pass
    except RuntimeError:
        if not fail_on_start:
            raise
    start = next((m for m in sent if m["type"] == "http.response.start"), None)
    data = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    result_headers = dict(start["headers"]) if start else {}
    return (start["status"] if start else 0), result_headers, data, sent


def json_body(data):
    return json.loads(data.decode()) if data else None
