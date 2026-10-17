from fastapi import APIRouter, Depends, Request, Response

from app.api.deps import PushTokenDep, require_configured
from app.auth.dependencies import AuthServiceDep
from app.gmail.dependencies import GmailPushServiceDep

router = APIRouter(prefix="/pubsub", tags=["gmail"])


@router.post("/gmail", status_code=204, dependencies=[Depends(require_configured)])
async def receive_gmail_push_api(
    request: Request,
    token: PushTokenDep,
    auth: AuthServiceDep,
    gmail: GmailPushServiceDep,
) -> Response:
    # Authenticate before reading the body, so unauthenticated callers get nothing parsed.
    await auth.verify_push_token(token)
    gmail.accept(await request.body())
    return Response(status_code=204)
