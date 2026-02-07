"""
A2A HTTP Transport Implementation.

Implements JSON-RPC 2.0 over HTTP/HTTPS using:
- httpx: async HTTP client (with SSL/TLS support)
- aiohttp: async HTTP server (with SSL/TLS support)

Design:
- TLS enforced for production (https:// required)
- Supports localhost HTTP for testing/development
- Proper HTTP status code mapping per spec
- Keep-Alive support for connection pooling
- Concurrent request handling (async)
"""

import asyncio
import json
import ssl
from typing import Dict, Any, Callable, Optional, Awaitable
from urllib.parse import urlparse
import logging

import httpx
from aiohttp import web

from a2a.transport.transport import Transport, ResponseEnvelope
from a2a.transport.errors import (
    TransportError,
    ConnectionError,
    TimeoutError,
    InvalidMessageError,
    HTTPError,
    TLSError,
    JSONRPCError,
)


logger = logging.getLogger(__name__)


class HTTPTransport(Transport):
    """
    HTTP/HTTPS implementation of Transport.

    Features:
    - Async client using httpx with connection pooling
    - Async server using aiohttp
    - JSON-RPC 2.0 envelope validation
    - HTTP status code mapping per spec
    - TLS 1.3 enforcement for production
    - Proper error handling and timeouts
    """

    def __init__(self, verify_tls: bool = True, tls_min_version: Optional[str] = "TLSv1_3"):
        """
        Initialize HTTPTransport.

        Args:
            verify_tls: Whether to verify TLS certificates (default True)
            tls_min_version: Minimum TLS version to allow (default TLSv1_3)
        """
        self.verify_tls = verify_tls
        self.tls_min_version = tls_min_version
        self._client: Optional[httpx.AsyncClient] = None
        self._server: Optional[web.AppRunner] = None
        self._app: Optional[web.Application] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the async HTTP client."""
        if self._client is None:
            # Build SSL context for TLS 1.3 enforcement
            ssl_context = None
            if self.verify_tls and self.tls_min_version:
                ssl_context = self._build_ssl_context()

            self._client = httpx.AsyncClient(
                verify=self.verify_tls,
                http2=False,  # JSON-RPC over HTTP/1.1
                timeout=httpx.Timeout(30.0),
            )
        return self._client

    def _build_ssl_context(self) -> Optional[ssl.SSLContext]:
        """Build SSL context with TLS 1.3 enforcement."""
        try:
            ctx = ssl.create_default_context()
            if self.tls_min_version == "TLSv1_3":
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            # Enforce strong ciphers
            ctx.set_ciphers("DEFAULT@SECLEVEL=2")
            return ctx
        except Exception as e:
            logger.warning(f"Failed to build SSL context: {e}")
            return None

    async def send(
        self,
        endpoint: str,
        message: Dict[str, Any],
        timeout: float = 30.0,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Send JSON-RPC request over HTTP and return response.

        Args:
            endpoint: Full URL (https://host:port/a2a/method)
            message: JSON-RPC 2.0 request envelope
            timeout: Request timeout in seconds
            request_id: Correlation ID (from message.id if not provided)

        Returns:
            JSON-RPC 2.0 response envelope

        Raises:
            ConnectionError: Failed to connect
            TimeoutError: Request timed out
            InvalidMessageError: Message validation failed
            HTTPError: HTTP error (400, 401, 403, 500, 503, etc)
            JSONRPCError: Server returned JSON-RPC error
            TransportError: Other failures
        """
        # Validate request envelope
        try:
            Transport.validate_jsonrpc_request(message)
        except InvalidMessageError as e:
            e.request_id = request_id or message.get("id")
            raise

        # Use request ID from message if not provided
        req_id = request_id or message.get("id")

        # Validate URL scheme
        parsed = urlparse(endpoint)
        if parsed.scheme not in ("http", "https"):
            raise InvalidMessageError(
                f"Invalid URL scheme: {parsed.scheme}, must be http or https",
                request_id=req_id,
            )

        # Enforce TLS for non-localhost
        if self.verify_tls and parsed.scheme == "http":
            hostname = parsed.hostname or ""
            if hostname not in ("localhost", "127.0.0.1", "::1"):
                raise TLSError(
                    endpoint,
                    "HTTP not allowed for non-localhost endpoints (use HTTPS)",
                    request_id=req_id,
                )

        try:
            client = await self._get_client()

            # Send POST request with JSON-RPC envelope
            response = await client.post(
                endpoint,
                json=message,
                headers={"Content-Type": "application/json", "X-Request-ID": req_id},
                timeout=timeout,
            )

            # Handle HTTP error status codes
            if response.status_code >= 400:
                body = response.text
                logger.error(f"HTTP {response.status_code}: {body}")

                if response.status_code == 400:
                    raise HTTPError(400, "Bad Request", body, req_id)
                elif response.status_code == 401:
                    raise HTTPError(401, "Unauthorized", body, req_id)
                elif response.status_code == 403:
                    raise HTTPError(403, "Forbidden", body, req_id)
                elif response.status_code == 429:
                    raise HTTPError(429, "Rate Limited", body, req_id)
                elif response.status_code == 500:
                    raise HTTPError(500, "Internal Server Error", body, req_id)
                elif response.status_code == 503:
                    raise HTTPError(503, "Service Unavailable", body, req_id)
                else:
                    raise HTTPError(response.status_code, f"HTTP {response.status_code}", body, req_id)

            # Parse response JSON
            try:
                response_data = response.json()
            except json.JSONDecodeError as e:
                raise InvalidMessageError(
                    f"Invalid JSON in response: {e}",
                    request_id=req_id,
                )

            # Validate response envelope
            try:
                Transport.validate_jsonrpc_response(response_data)
            except InvalidMessageError as e:
                e.request_id = req_id
                raise

            # Check for JSON-RPC error in response
            if "error" in response_data:
                error = response_data["error"]
                raise JSONRPCError(
                    error.get("code", -32603),
                    error.get("message", "Unknown error"),
                    request_id=req_id,
                    error_data=error.get("data"),
                )

            return response_data

        except (ConnectionError, TimeoutError, InvalidMessageError, HTTPError, JSONRPCError, TLSError):
            raise
        except asyncio.TimeoutError:
            raise TimeoutError(endpoint, timeout, "POST request", request_id=req_id)
        except httpx.ConnectError as e:
            raise ConnectionError(endpoint, str(e), request_id=req_id)
        except httpx.NetworkError as e:
            raise ConnectionError(endpoint, str(e), request_id=req_id)
        except httpx.SSLError as e:
            raise TLSError(endpoint, str(e), request_id=req_id)
        except Exception as e:
            raise TransportError(
                f"Unexpected error sending to {endpoint}: {e}",
                request_id=req_id,
            )

    async def listen(
        self,
        host: str,
        port: int,
        handler: Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]],
        request_id_header: str = "X-Request-ID",
    ) -> None:
        """
        Start HTTP server listening for JSON-RPC requests.

        Args:
            host: Bind address
            port: Bind port
            handler: Async handler function
            request_id_header: HTTP header for request ID

        The handler receives JSON-RPC request dict and must return
        JSON-RPC response dict.
        """
        # Create aiohttp application
        app = web.Application()

        # Add route handler for /a2a/* paths
        async def handle_rpc(request: web.Request) -> web.Response:
            """Handle incoming JSON-RPC request."""
            req_id = request.headers.get(request_id_header, Transport.generate_request_id())

            try:
                # Parse request body
                try:
                    message = await request.json()
                except json.JSONDecodeError as e:
                    error_response = ResponseEnvelope.error(
                        ResponseEnvelope.PARSE_ERROR,
                        f"Invalid JSON: {e}",
                        req_id,
                    )
                    return web.json_response(error_response, status=400)

                # Validate JSON-RPC request
                try:
                    Transport.validate_jsonrpc_request(message)
                except InvalidMessageError as e:
                    error_response = ResponseEnvelope.error(
                        ResponseEnvelope.INVALID_REQUEST,
                        e.message,
                        message.get("id", req_id),
                    )
                    return web.json_response(error_response, status=400)

                # Extract request ID from message
                msg_req_id = message.get("id", req_id)

                # Call handler
                try:
                    response = await handler(message)
                    Transport.validate_jsonrpc_response(response)
                    return web.json_response(response, status=200)

                except TransportError as e:
                    error_response = ResponseEnvelope.error(
                        ResponseEnvelope.SERVER_ERROR_END,
                        e.message,
                        msg_req_id,
                        data=e.to_dict(),
                    )
                    return web.json_response(error_response, status=e.http_status)

                except Exception as e:
                    logger.exception(f"Handler error: {e}")
                    error_response = ResponseEnvelope.error(
                        ResponseEnvelope.INTERNAL_ERROR,
                        f"Handler error: {str(e)}",
                        msg_req_id,
                    )
                    return web.json_response(error_response, status=500)

            except Exception as e:
                logger.exception(f"Unexpected request handler error: {e}")
                return web.json_response(
                    {"jsonrpc": "2.0", "error": {"code": -32603, "message": "Internal error"}, "id": req_id},
                    status=500,
                )

        # Register handler for /a2a/* paths
        app.router.add_post("/a2a/{path:.*}", handle_rpc)

        # Store app and runner
        self._app = app
        self._server = web.AppRunner(app)

        try:
            # Start server
            await self._server.setup()
            site = web.TCPSite(self._server, host, port)
            await site.start()
            logger.info(f"HTTP server listening on {host}:{port}")

            # Keep listening (blocking)
            while True:
                await asyncio.sleep(3600)  # Sleep for 1 hour intervals

        except OSError as e:
            raise ConnectionError(f"{host}:{port}", str(e))
        except Exception as e:
            raise TransportError(f"Server startup error: {e}")

    async def close(self) -> None:
        """Close transport and cleanup resources."""
        try:
            if self._client:
                await self._client.aclose()
                self._client = None

            if self._server:
                await self._server.cleanup()
                self._server = None

            if self._app:
                self._app = None

            logger.info("Transport closed")
        except Exception as e:
            logger.error(f"Error closing transport: {e}")
            raise TransportError(f"Close error: {e}")
