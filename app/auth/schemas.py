from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

INSTALLATION_ID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"


class IdentityClaims(BaseModel):
    # Verified ID tokens carry more claims than these; the rest are ignored, not rejected.
    model_config = ConfigDict(frozen=True, extra="ignore", strict=True)

    iss: str
    aud: str | list[str]
    sub: str
    exp: float = Field(allow_inf_nan=False)
    iat: float = Field(allow_inf_nan=False)
    email: Optional[str] = None
    email_verified: Optional[bool] = None
    nonce: Optional[str] = None
    hd: Optional[str] = None


class SessionRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id_token: str = Field(min_length=1, max_length=16384)
    nonce: str = Field(min_length=16, max_length=256)
    installation_id: str = Field(pattern=INSTALLATION_ID_PATTERN)


class SessionInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id_token: str
    nonce: str
    installation_id: str

    @classmethod
    def from_request(cls, request: SessionRequest) -> "SessionInput":
        return cls(
            id_token=request.id_token,
            nonce=request.nonce,
            installation_id=request.installation_id,
        )


class ChallengeData(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    nonce: str
    expires_in: int


class ChallengeResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    nonce: str
    expires_in: int

    @classmethod
    def from_data(cls, data: ChallengeData) -> "ChallengeResponse":
        return cls(nonce=data.nonce, expires_in=data.expires_in)


class SessionResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: str


class RefreshRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    refresh_token: str = Field(min_length=1, max_length=256)
