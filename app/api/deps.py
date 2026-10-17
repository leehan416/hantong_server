import re
from typing import Annotated

from fastapi import Depends, Request

from app.api.exception.exceptions import ServiceUnavailableError, TooManyRequestsError
from app.auth.exceptions import InvalidCredentialsError

SESSION_TOKEN_PATTERN = re.compile(r"Bearer ([A-Za-z0-9._~-]{20,256})")
# Google-signed OIDC JWTs are much longer than our session tokens.
PUSH_TOKEN_PATTERN = re.compile(r"Bearer ([A-Za-z0-9._~-]{20,16384})")


def require_configured(request: Request) -> None:
    if not request.app.state.settings.configured:
        raise ServiceUnavailableError


def client_ip(request: Request) -> str:
    # ponytail: peer address; behind the reverse proxy set FORWARDED_ALLOW_IPS to its address
    if not request.client:
        return "unknown"
    return request.client.host


def limit_auth_requests(request: Request) -> None:
    if not request.app.state.auth_limiter.allow(client_ip(request), request.app.state.clock()):
        raise TooManyRequestsError


def limit_stream_requests(request: Request) -> None:
    if not request.app.state.stream_limiter.allow(client_ip(request), request.app.state.clock()):
        raise TooManyRequestsError


def bearer_token(request: Request, pattern: re.Pattern[str]) -> str:
    match = pattern.fullmatch(request.headers.get("authorization", ""))
    if not match:
        raise InvalidCredentialsError
    return match.group(1)


def get_session_token(request: Request) -> str:
    return bearer_token(request, SESSION_TOKEN_PATTERN)


def get_push_token(request: Request) -> str:
    return bearer_token(request, PUSH_TOKEN_PATTERN)


SessionTokenDep = Annotated[str, Depends(get_session_token)]
PushTokenDep = Annotated[str, Depends(get_push_token)]
