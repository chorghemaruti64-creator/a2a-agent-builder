"""
A2A Transport Layer Errors.

Defines transport-specific exceptions for HTTP/network operations.
All errors inherit from A2AError base class for consistency.
"""

from typing import Optional, Dict, Any
from a2a.core.errors import A2AError


class TransportError(A2AError):
    """Base exception for transport layer errors."""

    def __init__(
        self,
        message: str,
        code: str = "TRANSPORT_ERROR",
        details: Optional[Dict[str, Any]] = None,
        recoverable: bool = True,
        request_id: Optional[str] = None,
        http_status: int = 500,
    ):
        super().__init__(
            code=code,
            message=message,
            details=details or {},
            recoverable=recoverable,
            request_id=request_id,
            http_status=http_status,
        )


class ConnectionError(TransportError):
    """Failed to establish connection."""

    def __init__(
        self,
        endpoint: str,
        reason: str,
        request_id: Optional[str] = None,
    ):
        super().__init__(
            code="CONNECTION_ERROR",
            message=f"Failed to connect to {endpoint}: {reason}",
            details={"endpoint": endpoint, "reason": reason},
            recoverable=True,
            request_id=request_id,
            http_status=503,
        )


class TimeoutError(TransportError):
    """Transport operation timed out."""

    def __init__(
        self,
        endpoint: str,
        timeout_seconds: float,
        operation: str = "request",
        request_id: Optional[str] = None,
    ):
        super().__init__(
            code="TRANSPORT_TIMEOUT",
            message=f"Transport {operation} to {endpoint} timed out after {timeout_seconds}s",
            details={
                "endpoint": endpoint,
                "timeout_seconds": timeout_seconds,
                "operation": operation,
            },
            recoverable=True,
            request_id=request_id,
            http_status=504,
        )


class InvalidMessageError(TransportError):
    """Message format or content is invalid."""

    def __init__(
        self,
        reason: str,
        details: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
    ):
        super().__init__(
            code="INVALID_MESSAGE",
            message=f"Invalid message: {reason}",
            details=details or {},
            recoverable=False,
            request_id=request_id,
            http_status=400,
        )


class HTTPError(TransportError):
    """HTTP-specific error with status code."""

    def __init__(
        self,
        status_code: int,
        message: str,
        response_body: Optional[str] = None,
        request_id: Optional[str] = None,
    ):
        # Determine if recoverable based on status code
        recoverable = status_code >= 500 or status_code == 429
        
        # Determine appropriate code
        code_map = {
            400: "BAD_REQUEST",
            401: "UNAUTHORIZED",
            403: "FORBIDDEN",
            404: "NOT_FOUND",
            429: "RATE_LIMITED",
            500: "SERVER_ERROR",
            503: "SERVICE_UNAVAILABLE",
        }
        code = code_map.get(status_code, "HTTP_ERROR")
        
        super().__init__(
            code=code,
            message=message,
            details={"status_code": status_code, "response_body": response_body},
            recoverable=recoverable,
            request_id=request_id,
            http_status=status_code,
        )
        self.status_code = status_code
        self.response_body = response_body


class TLSError(TransportError):
    """TLS/HTTPS certificate or validation error."""

    def __init__(
        self,
        endpoint: str,
        reason: str,
        request_id: Optional[str] = None,
    ):
        super().__init__(
            code="TLS_ERROR",
            message=f"TLS error for {endpoint}: {reason}",
            details={"endpoint": endpoint, "reason": reason},
            recoverable=False,
            request_id=request_id,
            http_status=400,
        )


class JSONRPCError(TransportError):
    """JSON-RPC protocol error."""

    def __init__(
        self,
        error_code: int,
        error_message: str,
        request_id: Optional[str] = None,
        error_data: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            code="JSONRPC_ERROR",
            message=f"JSON-RPC error {error_code}: {error_message}",
            details={
                "jsonrpc_error_code": error_code,
                "jsonrpc_error_message": error_message,
                "jsonrpc_error_data": error_data,
            },
            recoverable=False,
            request_id=request_id,
            http_status=400,
        )
