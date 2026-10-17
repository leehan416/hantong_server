from fastapi import APIRouter, Depends, Response

from app.api.deps import limit_auth_requests, require_configured
from app.auth.dependencies import AuthServiceDep
from app.auth.schemas import (
    ChallengeResponse,
    RefreshRequest,
    SessionInput,
    SessionRequest,
    SessionResponse,
)
from app.relay.dependencies import CurrentSessionDep, RelayServiceDep

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/challenge",
    response_model=ChallengeResponse,
    dependencies=[Depends(require_configured), Depends(limit_auth_requests)],
)
async def create_challenge_api(auth: AuthServiceDep) -> ChallengeResponse:
    return ChallengeResponse.from_data(auth.create_challenge())


@router.post(
    "/session",
    response_model=SessionResponse,
    dependencies=[Depends(require_configured), Depends(limit_auth_requests)],
)
async def create_session_api(body: SessionRequest, auth: AuthServiceDep) -> SessionResponse:
    issued = await auth.create_session(SessionInput.from_request(body))
    return SessionResponse(
        access_token=issued.access_token,
        expires_in=issued.expires_in,
        refresh_token=issued.refresh_token,
    )


@router.post(
    "/refresh",
    response_model=SessionResponse,
    dependencies=[Depends(require_configured), Depends(limit_auth_requests)],
)
async def refresh_session_api(body: RefreshRequest, relay: RelayServiceDep) -> SessionResponse:
    issued = relay.refresh(body.refresh_token)
    return SessionResponse(
        access_token=issued.access_token,
        expires_in=issued.expires_in,
        refresh_token=issued.refresh_token,
    )


@router.delete("/session", status_code=204)
async def logout_api(session: CurrentSessionDep, relay: RelayServiceDep) -> Response:
    relay.revoke(session)
    return Response(status_code=204)
