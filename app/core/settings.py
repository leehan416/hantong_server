import re
from typing import Optional
from urllib.parse import urlsplit

from pydantic_settings import BaseSettings, SettingsConfigDict

SERVICE_ACCOUNT_PATTERN = re.compile(r"[^@\s]+@[^@\s]+\.gserviceaccount\.com", re.I)
SUBSCRIPTION_PATTERN = re.compile(r"projects/[A-Za-z0-9:._-]+/subscriptions/[A-Za-z0-9._~-]+")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(frozen=True, extra="ignore")

    GOOGLE_CLIENT_ID: Optional[str] = None
    PUBSUB_AUDIENCE: Optional[str] = None
    PUBSUB_SERVICE_ACCOUNT_EMAIL: Optional[str] = None
    PUBSUB_SUBSCRIPTION: Optional[str] = None
    LOG_LEVEL: str = "INFO"

    @property
    def configured(self) -> bool:
        """Fail closed: every Google/Pub/Sub value must be present and well formed."""
        values = (
            self.GOOGLE_CLIENT_ID,
            self.PUBSUB_AUDIENCE,
            self.PUBSUB_SERVICE_ACCOUNT_EMAIL,
            self.PUBSUB_SUBSCRIPTION,
        )
        for value in values:
            if not value or not value.strip():
                return False
            for char in value:
                if ord(char) < 32 or char.isspace():
                    return False
        if not valid_audience(str(self.PUBSUB_AUDIENCE)):
            return False
        if not SERVICE_ACCOUNT_PATTERN.fullmatch(str(self.PUBSUB_SERVICE_ACCOUNT_EMAIL)):
            return False
        return SUBSCRIPTION_PATTERN.fullmatch(str(self.PUBSUB_SUBSCRIPTION)) is not None


def valid_audience(value: str) -> bool:
    try:
        audience = urlsplit(value)
        audience.port  # noqa: B018 - raises ValueError on a malformed port
    except ValueError:
        return False
    if audience.username is not None or audience.password is not None:
        return False
    if audience.fragment or not audience.hostname:
        return False
    if audience.scheme == "https":
        return True
    return audience.scheme == "http" and audience.hostname == "127.0.0.1"


settings = Settings()
