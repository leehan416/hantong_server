from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Pub/Sub and Gmail add fields over time; unknown ones are ignored, not rejected.
EXTERNAL_PAYLOAD_CONFIG = ConfigDict(frozen=True, extra="ignore", strict=True)


class PubSubMessage(BaseModel):
    model_config = EXTERNAL_PAYLOAD_CONFIG

    message_id: str = Field(alias="messageId", min_length=1, max_length=256, pattern=r"\S")
    data: str = Field(max_length=24000)


class PubSubEnvelope(BaseModel):
    model_config = EXTERNAL_PAYLOAD_CONFIG

    subscription: str = Field(min_length=1)
    message: PubSubMessage


class GmailNotification(BaseModel):
    model_config = EXTERNAL_PAYLOAD_CONFIG

    email_address: str = Field(alias="emailAddress", max_length=320)
    history_id: str = Field(alias="historyId", pattern=r"^[1-9][0-9]*$")

    @field_validator("history_id", mode="before")
    @classmethod
    def history_id_as_text(cls, value: Any) -> Any:
        # Gmail sends historyId as a JSON number, though its docs show a string.
        if isinstance(value, int) and not isinstance(value, bool):
            return str(value)
        return value
