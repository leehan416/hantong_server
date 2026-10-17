from app.api.exception.codes import ErrorCode
from app.api.exception.exceptions import ApplicationError, UnauthorizedError


class InvalidCredentialsError(UnauthorizedError):
    """One generic error for every rejected token, nonce or session, so callers learn nothing."""

    error_code = ErrorCode.AUTH_INVALID_CREDENTIALS
    default_message = "Unauthorized"


class CapacityExceededError(ApplicationError):
    error_code = ErrorCode.AUTH_CAPACITY_EXCEEDED
    default_message = "Capacity exceeded"


class IdentityVerifierUnavailableError(ApplicationError):
    error_code = ErrorCode.AUTH_VERIFIER_UNAVAILABLE
    default_message = "Service unavailable"
