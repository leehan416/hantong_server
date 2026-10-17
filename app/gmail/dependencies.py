from typing import Annotated

from fastapi import Depends, Request

from app.gmail.service import GmailPushService


def get_gmail_push_service(request: Request) -> GmailPushService:
    return request.app.state.gmail_push_service


GmailPushServiceDep = Annotated[GmailPushService, Depends(get_gmail_push_service)]
