from typing import Optional

from app.api.exception.codes import ErrorCode


class ApplicationError(Exception):
    error_code = ErrorCode.INTERNAL_SERVER_ERROR
    default_message = "Internal Server Error"

    def __init__(self, message: Optional[str] = None) -> None:
        self.message = self.default_message
        if message is not None:
            self.message = message
        super().__init__(self.message)


class BadRequestError(ApplicationError):
    error_code = ErrorCode.BAD_REQUEST
    default_message = "Bad Request"


class UnauthorizedError(ApplicationError):
    error_code = ErrorCode.UNAUTHORIZED
    default_message = "Unauthorized"


class ForbiddenError(ApplicationError):
    error_code = ErrorCode.FORBIDDEN
    default_message = "Forbidden"


class NotFoundError(ApplicationError):
    error_code = ErrorCode.NOT_FOUND
    default_message = "Not Found"


class MethodNotAllowedError(ApplicationError):
    error_code = ErrorCode.METHOD_NOT_ALLOWED
    default_message = "Method Not Allowed"


class ConflictError(ApplicationError):
    error_code = ErrorCode.CONFLICT
    default_message = "Conflict"


class UnprocessableEntityError(ApplicationError):
    error_code = ErrorCode.UNPROCESSABLE_ENTITY
    default_message = "Unprocessable Entity"


class TooManyRequestsError(ApplicationError):
    error_code = ErrorCode.TOO_MANY_REQUESTS
    default_message = "Rate limit exceeded"


class InternalServerError(ApplicationError):
    pass


class ServiceUnavailableError(ApplicationError):
    error_code = ErrorCode.SERVICE_UNAVAILABLE
    default_message = "Service unavailable"
