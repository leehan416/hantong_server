from typing import Annotated

from fastapi import Depends, Request

from app.api.deps import SessionTokenDep
from app.relay.service import RelayService, RelaySession


def get_relay_service(request: Request) -> RelayService:
    return request.app.state.relay


RelayServiceDep = Annotated[RelayService, Depends(get_relay_service)]


def get_current_session(token: SessionTokenDep, relay: RelayServiceDep) -> RelaySession:
    return relay.authenticate(token)


CurrentSessionDep = Annotated[RelaySession, Depends(get_current_session)]
