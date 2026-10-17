from pydantic import BaseModel, ConfigDict, Field

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
