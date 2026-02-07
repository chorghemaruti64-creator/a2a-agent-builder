"""
A2A Transport Layer.

Provides pluggable transport implementations for A2A Protocol communication.

Available transports:
- HTTPTransport: JSON-RPC 2.0 over HTTP/HTTPS with aiohttp + httpx

Error types:
- TransportError: Base transport exception
- ConnectionError: Connection failures
- TimeoutError: Operation timeouts
- InvalidMessageError: Message format errors
- HTTPError: HTTP protocol errors
- TLSError: TLS/SSL failures
- JSONRPCError: JSON-RPC protocol errors

Examples:

    # Client: send a request
    from a2a.transport import HTTPTransport, RequestEnvelope
    
    transport = HTTPTransport()
    request = RequestEnvelope.create(
        method="handshake/hello",
        params={"nonce": "...", "did": "..."}
    )
    response = await transport.send(
        "https://server:5000/a2a/handshake",
        request
    )

    # Server: listen and handle requests
    async def handler(message):
        method = message["method"]
        params = message["params"]
        # Process request...
        return {
            "jsonrpc": "2.0",
            "result": {"session": "..."},
            "id": message["id"]
        }
    
    transport = HTTPTransport()
    await transport.listen("0.0.0.0", 5000, handler)
"""

from a2a.transport.transport import Transport, RequestEnvelope, ResponseEnvelope
from a2a.transport.http import HTTPTransport
from a2a.transport.errors import (
    TransportError,
    ConnectionError,
    TimeoutError,
    InvalidMessageError,
    HTTPError,
    TLSError,
    JSONRPCError,
)

__all__ = [
    # Transport base class
    "Transport",
    "RequestEnvelope",
    "ResponseEnvelope",
    # HTTP implementation
    "HTTPTransport",
    # Errors
    "TransportError",
    "ConnectionError",
    "TimeoutError",
    "InvalidMessageError",
    "HTTPError",
    "TLSError",
    "JSONRPCError",
]
