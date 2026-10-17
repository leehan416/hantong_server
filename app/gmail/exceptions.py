from app.api.exception.codes import ErrorCode
from app.api.exception.exceptions import BadRequestError


class InvalidNotificationError(BadRequestError):
    error_code = ErrorCode.GMAIL_INVALID_NOTIFICATION
    default_message = "Invalid request"
