import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI

from app.api.exception.handlers import setup_exception_handlers
from app.api.router import api_router
from app.auth.adapters.google.token_verifier import GoogleIdentityTokenVerifier
from app.auth.ports import IdentityTokenVerifier
from app.auth.service import AuthService
from app.core.logger import setup_logging
from app.core.middleware import BodyGuard
from app.core.rate_limit import SlidingLimit
from app.core.settings import Settings
from app.core.settings import settings as default_settings
from app.gmail.service import GmailPushService
from app.relay.service import RelayService


def create_app(
    settings: Settings = default_settings,
    identity_verifier: Optional[IdentityTokenVerifier] = None,
    clock: Callable[[], float] = time.time,
) -> FastAPI:
    """Assembly point: the only place that picks concrete adapters."""
    if not identity_verifier:
        identity_verifier = GoogleIdentityTokenVerifier()
    relay = RelayService(clock)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        setup_logging(settings.LOG_LEVEL)
        try:
            yield
        finally:
            relay.close()

    app = FastAPI(lifespan=lifespan)
    app.state.settings = settings
    app.state.clock = clock
    app.state.relay = relay
    app.state.auth_service = AuthService(settings, relay, identity_verifier, clock)
    app.state.gmail_push_service = GmailPushService(settings, relay)
    app.state.auth_limiter = SlidingLimit(20)
    app.state.stream_limiter = SlidingLimit(60)

    setup_exception_handlers(app)
    app.include_router(api_router)
    app.add_middleware(BodyGuard)
    return app


app = create_app()
