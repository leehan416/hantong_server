from typing import Annotated

from fastapi import Depends, Request

from app.auth.service import AuthService


def get_auth_service(request: Request) -> AuthService:
    return request.app.state.auth_service


AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]
