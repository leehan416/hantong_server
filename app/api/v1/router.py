from fastapi import APIRouter, Request

from app.auth.router import router as auth_router
from app.gmail.router import router as gmail_router
from app.relay.router import router as relay_router

router = APIRouter(prefix="/api/v1")
router.include_router(auth_router)
router.include_router(relay_router)
router.include_router(gmail_router)


@router.get("/health/live", tags=["health"])
async def liveness_api(request: Request) -> dict[str, object]:
    return {"status": "ok", "configured": request.app.state.settings.configured}
