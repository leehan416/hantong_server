import base64
import binascii

from pydantic import ValidationError

from app.core.settings import Settings
from app.gmail.exceptions import InvalidNotificationError
from app.gmail.schemas import GmailNotification, PubSubEnvelope
from app.relay.service import RelayService


class GmailPushService:
    def __init__(self, settings: Settings, relay: RelayService) -> None:
        self.settings = settings
        self.relay = relay

    def accept(self, body: bytes) -> None:
        envelope = parse_envelope(body)
        if envelope.subscription != self.settings.PUBSUB_SUBSCRIPTION:
            raise InvalidNotificationError
        notification = decode_notification(envelope.message.data)
        self.relay.publish(
            envelope.message.message_id,
            notification.email_address,
            notification.history_id,
        )


def parse_envelope(body: bytes) -> PubSubEnvelope:
    try:
        return PubSubEnvelope.model_validate_json(body)
    except ValidationError:
        raise InvalidNotificationError from None


def decode_notification(data: str) -> GmailNotification:
    try:
        payload = base64.b64decode(data, validate=True)
    except binascii.Error:
        raise InvalidNotificationError from None
    try:
        return GmailNotification.model_validate_json(payload)
    except ValidationError:
        raise InvalidNotificationError from None
