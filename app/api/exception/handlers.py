from collections.abc import Mapping
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.exception.codes import ErrorCode
from app.api.exception.exceptions import ApplicationError
from app.core.logger import logger


def error_response(
    error_code: ErrorCode,
    message: str,
    headers: Optional[Mapping[str, str]] = None,
    status_code: Optional[int] = None,
) -> JSONResponse:
    if status_code is None:
        status_code = error_code.http_status
    return JSONResponse(
        status_code=status_code,
        content={
            "code": error_code.value,
            "message": message,
        },
        headers=headers,
    )


def find_common_error_code(status_code: int) -> Optional[ErrorCode]:
    for code in ErrorCode:
        if code.is_common and code.http_status == status_code:
            return code
    return None


def find_detail_error_code(detail: object) -> Optional[ErrorCode]:
    if not isinstance(detail, dict):
        return None
    try:
        return ErrorCode(detail.get("code"))
    except (TypeError, ValueError):
        return None


def detail_message(detail: object) -> str:
    if not isinstance(detail, dict):
        return str(detail)
    message = detail.get("message")
    if isinstance(message, str):
        return message
    return str(detail)


async def application_error_handler(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, ApplicationError):
        raise exc

    return error_response(exc.error_code, exc.message)


async def request_validation_error_handler(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, RequestValidationError):
        raise exc

    return error_response(ErrorCode.UNPROCESSABLE_ENTITY, "Request validation failed")


async def http_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, StarletteHTTPException):
        raise exc

    status_code = None
    error_code = find_detail_error_code(exc.detail)
    if error_code is None:
        error_code = find_common_error_code(exc.status_code)
    if error_code is None:
        # Keep the real status and report the generic code for its class.
        status_code = exc.status_code
        error_code = ErrorCode.BAD_REQUEST
        if exc.status_code >= 500:
            error_code = ErrorCode.INTERNAL_SERVER_ERROR

    message = "Internal Server Error"
    if error_code is not ErrorCode.INTERNAL_SERVER_ERROR:
        message = detail_message(exc.detail)
    return error_response(error_code, message, headers=exc.headers, status_code=status_code)


async def internal_server_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return error_response(ErrorCode.INTERNAL_SERVER_ERROR, "Internal Server Error")


def setup_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(ApplicationError, application_error_handler)
    app.add_exception_handler(RequestValidationError, request_validation_error_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(Exception, internal_server_exception_handler)
