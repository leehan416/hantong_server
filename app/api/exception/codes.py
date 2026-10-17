from enum import Enum


class ErrorCode(str, Enum):
    # Common
    BAD_REQUEST = "COMMON_400"
    UNAUTHORIZED = "COMMON_401"
    FORBIDDEN = "COMMON_403"
    NOT_FOUND = "COMMON_404"
    METHOD_NOT_ALLOWED = "COMMON_405"
    REQUEST_TIMEOUT = "COMMON_408"
    CONFLICT = "COMMON_409"
    PAYLOAD_TOO_LARGE = "COMMON_413"
    UNPROCESSABLE_ENTITY = "COMMON_422"
    TOO_MANY_REQUESTS = "COMMON_429"
    INTERNAL_SERVER_ERROR = "COMMON_500"
    SERVICE_UNAVAILABLE = "COMMON_503"

    # Auth
    AUTH_INVALID_CREDENTIALS = "AUTH_401"
    AUTH_CAPACITY_EXCEEDED = "AUTH_429"
    AUTH_VERIFIER_UNAVAILABLE = "AUTH_503"

    # Relay
    RELAY_STREAM_ACTIVE = "RELAY_409"

    # Gmail
    GMAIL_INVALID_NOTIFICATION = "GMAIL_400"

    @property
    def http_status(self) -> int:
        return int(self.value.split("_", 2)[1])

    @property
    def is_common(self) -> bool:
        return self.value.startswith("COMMON_")
