from pydantic import BaseModel, ConfigDict


class IssuedSession(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    access_token: str
    expires_in: int
    refresh_token: str
