from typing import Any, Optional
from fastapi import HTTPException, status


class SentinelException(HTTPException):
    def __init__(
        self,
        status_code: int,
        error_code: str,
        message: str,
        details: Optional[Any] = None,
    ):
        self.error_code = error_code
        self.message = message
        self.details = details
        super().__init__(
            status_code=status_code,
            detail={"code": error_code, "message": message, "details": details},
        )


class NotFoundException(SentinelException):
    def __init__(self, resource: str, identifier: str = ""):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            error_code="RESOURCE_NOT_FOUND",
            message=f"{resource} {identifier} was not found." if identifier else f"{resource} not found.",
        )


class UnauthorizedException(SentinelException):
    def __init__(self, message: str = "Invalid authentication credentials."):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            error_code="UNAUTHORIZED",
            message=message,
        )


class ForbiddenException(SentinelException):
    def __init__(self, message: str = "You do not have permission to perform this action."):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="FORBIDDEN_OPERATION",
            message=message,
        )


class ValidationException(SentinelException):
    def __init__(self, message: str, details: Optional[Any] = None):
        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            error_code="VALIDATION_ERROR",
            message=message,
            details=details,
        )


class SSRFBlockedException(SentinelException):
    def __init__(self, message: str = "Target address is restricted by SSRF protection policy."):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            error_code="SSRF_RESTRICTION_TRIGGERED",
            message=message,
        )
