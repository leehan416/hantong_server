from app.api.exception.codes import ErrorCode
from app.api.exception.exceptions import ConflictError


class StreamActiveError(ConflictError):
    error_code = ErrorCode.RELAY_STREAM_ACTIVE
    default_message = "Stream already active"
