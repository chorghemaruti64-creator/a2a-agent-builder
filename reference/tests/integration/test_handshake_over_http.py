"""
A2A Handshake Protocol Integration Tests (Phase 4).

End-to-end tests for the complete 6-step handshake over HTTP transport.
Tests actual message flow:
1. HELLO (client) → server
2. CHALLENGE (server) → client
3. PROOF (client) → server
4. POLICY (server) → client
5. ACCEPT_POLICY (client) → server
6. SESSION (server) → client

Also tests error scenarios and server rejection of invalid requests.
"""

import pytest
import asyncio
import time
from typing import Dict, Any
import base64
import json

from a2a.transport import (
    HTTPTransport,
    RequestEnvelope,
    ResponseEnvelope,
)
from a2a.transport.errors import InvalidMessageError, HTTPError
from a2a.protocol.handshake.messages import (
    HelloMessage,
    ChallengeMessage,
    ProofMessage,
    PolicyMessage,
    AcceptPolicyMessage,
    SessionMessage,
    MessageType,
)
from a2a.security.crypto import b64url_encode


def create_valid_nonce(length: int = 32) -> str:
    """Create a valid base64url-encoded nonce."""
    nonce_bytes = b"a" * length
    return b64url_encode(nonce_bytes)


def create_valid_manifest_hash() -> str:
    """Create a valid hex-encoded manifest hash (SHA-256)."""
    return "a" * 64


def create_valid_policy_hash() -> str:
    """Create a valid hex-encoded policy hash (SHA-256)."""
    return "b" * 64


class TestHandshakeOverHTTP:
    """Test full 6-step handshake over HTTP transport."""

    @pytest.mark.asyncio
    async def test_01_hello_challenge_exchange(self):
        """Test HELLO/CHALLENGE message exchange (steps 1-2)."""
        transport = HTTPTransport()

        # Server handler: respond to HELLO with CHALLENGE
        async def handler(message: Dict[str, Any]) -> Dict[str, Any]:
            method = message["method"]

            if method == "handshake/hello":
                # Validate HELLO message
                params = message["params"]
                try:
                    hello = HelloMessage(**params)
                except Exception as e:
                    return ResponseEnvelope.error(
                        ResponseEnvelope.INVALID_REQUEST,
                        str(e),
                        message["id"],
                    )

                # Create CHALLENGE response
                challenge = ChallengeMessage(
                    nonce_b=create_valid_nonce(),
                    policy_hash=create_valid_policy_hash(),
                    public_keys=[{"key": "test_key", "alg": "EdDSA"}],
                )

                return ResponseEnvelope.success(
                    challenge.model_dump(),
                    message["id"],
                )

            return ResponseEnvelope.error(
                ResponseEnvelope.METHOD_NOT_FOUND,
                f"Unknown method: {method}",
                message["id"],
            )

        # Start server
        listen_task = asyncio.create_task(
            transport.listen("127.0.0.1", 19990, handler)
        )
        await asyncio.sleep(0.5)

        try:
            # Create HELLO message
            hello = HelloMessage(
                nonce_a=create_valid_nonce(),
                agent_did="did:key:z123456789",
                manifest_hash=create_valid_manifest_hash(),
            )

            request = RequestEnvelope.create(
                method="handshake/hello",
                params=hello.model_dump(),
                request_id="hs-001",
            )

            # Send HELLO and get CHALLENGE
            response = await transport.send(
                "http://127.0.0.1:19990/a2a/handshake",
                request,
                timeout=5.0,
            )

            # Verify CHALLENGE response
            assert response["jsonrpc"] == "2.0"
            assert response["id"] == "hs-001"
            assert "result" in response
            challenge_data = response["result"]
            assert challenge_data["message_type"] == MessageType.CHALLENGE.value

            # Validate as proper CHALLENGE message
            challenge = ChallengeMessage(**challenge_data)
            assert challenge.nonce_b
            assert challenge.policy_hash
            assert len(challenge.public_keys) > 0

        finally:
            listen_task.cancel()
            try:
                await listen_task
            except asyncio.CancelledError:
                pass
            await transport.close()

    @pytest.mark.asyncio
    async def test_02_proof_policy_exchange(self):
        """Test PROOF/POLICY message exchange (steps 3-4)."""
        transport = HTTPTransport()

        # Server handler
        async def handler(message: Dict[str, Any]) -> Dict[str, Any]:
            method = message["method"]

            if method == "handshake/proof":
                params = message["params"]
                try:
                    proof = ProofMessage(**params)
                except Exception as e:
                    return ResponseEnvelope.error(
                        ResponseEnvelope.INVALID_REQUEST,
                        str(e),
                        message["id"],
                    )

                # Create POLICY response
                policy = PolicyMessage(
                    policy={"rate_limit": 100, "timeout": 3600},
                    signature="test.signature.value",
                )

                return ResponseEnvelope.success(
                    policy.model_dump(),
                    message["id"],
                )

            return ResponseEnvelope.error(
                ResponseEnvelope.METHOD_NOT_FOUND,
                f"Unknown method: {method}",
                message["id"],
            )

        listen_task = asyncio.create_task(
            transport.listen("127.0.0.1", 19991, handler)
        )
        await asyncio.sleep(0.5)

        try:
            # Create PROOF message
            proof = ProofMessage(
                nonce_a=create_valid_nonce(),
                nonce_b=create_valid_nonce(),
                proof="header.payload.signature",
            )

            request = RequestEnvelope.create(
                method="handshake/proof",
                params=proof.model_dump(),
                request_id="hs-002",
            )

            response = await transport.send(
                "http://127.0.0.1:19991/a2a/handshake",
                request,
                timeout=5.0,
            )

            # Verify POLICY response
            assert response["jsonrpc"] == "2.0"
            assert "result" in response
            policy_data = response["result"]
            assert policy_data["message_type"] == MessageType.POLICY.value

            # Validate as proper POLICY message
            policy = PolicyMessage(**policy_data)
            assert policy.policy
            assert policy.signature

        finally:
            listen_task.cancel()
            try:
                await listen_task
            except asyncio.CancelledError:
                pass
            await transport.close()

    @pytest.mark.asyncio
    async def test_03_accept_policy_session_exchange(self):
        """Test ACCEPT_POLICY/SESSION message exchange (steps 5-6)."""
        transport = HTTPTransport()

        # Server handler
        async def handler(message: Dict[str, Any]) -> Dict[str, Any]:
            method = message["method"]

            if method == "handshake/accept_policy":
                params = message["params"]
                try:
                    accept = AcceptPolicyMessage(**params)
                except Exception as e:
                    return ResponseEnvelope.error(
                        ResponseEnvelope.INVALID_REQUEST,
                        str(e),
                        message["id"],
                    )

                # Create SESSION response
                session = SessionMessage(
                    session_id="session-abc123-1234",
                    expires_at=int(time.time()) + 3600,
                    signature="session.signature.value",
                )

                return ResponseEnvelope.success(
                    session.model_dump(),
                    message["id"],
                )

            return ResponseEnvelope.error(
                ResponseEnvelope.METHOD_NOT_FOUND,
                f"Unknown method: {method}",
                message["id"],
            )

        listen_task = asyncio.create_task(
            transport.listen("127.0.0.1", 19992, handler)
        )
        await asyncio.sleep(0.5)

        try:
            # Create ACCEPT_POLICY message
            accept_policy = AcceptPolicyMessage(
                policy_hash=create_valid_policy_hash(),
                commitment="commitment.signature.value",
            )

            request = RequestEnvelope.create(
                method="handshake/accept_policy",
                params=accept_policy.model_dump(),
                request_id="hs-003",
            )

            response = await transport.send(
                "http://127.0.0.1:19992/a2a/handshake",
                request,
                timeout=5.0,
            )

            # Verify SESSION response
            assert response["jsonrpc"] == "2.0"
            assert "result" in response
            session_data = response["result"]
            assert session_data["message_type"] == MessageType.SESSION.value

            # Validate as proper SESSION message
            session = SessionMessage(**session_data)
            assert session.session_id == "session-abc123-1234"
            assert session.expires_at > int(time.time())

        finally:
            listen_task.cancel()
            try:
                await listen_task
            except asyncio.CancelledError:
                pass
            await transport.close()

    @pytest.mark.asyncio
    async def test_04_invalid_handshake_request(self):
        """Test server rejection of invalid handshake messages."""
        transport = HTTPTransport()

        # Server handler
        async def handler(message: Dict[str, Any]) -> Dict[str, Any]:
            method = message["method"]

            if method == "handshake/hello":
                try:
                    HelloMessage(**message["params"])
                    return ResponseEnvelope.success({}, message["id"])
                except Exception as e:
                    return ResponseEnvelope.error(
                        ResponseEnvelope.INVALID_REQUEST,
                        str(e),
                        message["id"],
                    )

            return ResponseEnvelope.error(
                ResponseEnvelope.METHOD_NOT_FOUND,
                f"Unknown method: {method}",
                message["id"],
            )

        listen_task = asyncio.create_task(
            transport.listen("127.0.0.1", 19993, handler)
        )
        await asyncio.sleep(0.5)

        try:
            # Create invalid HELLO (missing manifest_hash)
            invalid_hello = {
                "message_type": MessageType.HELLO.value,
                "nonce_a": create_valid_nonce(),
                "agent_did": "did:key:z123456789",
                # Missing manifest_hash - will cause validation error
            }

            request = RequestEnvelope.create(
                method="handshake/hello",
                params=invalid_hello,
                request_id="hs-bad-001",
            )

            # This should result in an error response from the server
            with pytest.raises(Exception):  # JSONRPCError expected
                await transport.send(
                    "http://127.0.0.1:19993/a2a/handshake",
                    request,
                    timeout=5.0,
                )

        finally:
            listen_task.cancel()
            try:
                await listen_task
            except asyncio.CancelledError:
                pass
            await transport.close()

    @pytest.mark.asyncio
    async def test_05_concurrent_handshake_requests(self):
        """Test concurrent handshake requests from multiple clients."""
        transport = HTTPTransport()

        # Server handler
        async def handler(message: Dict[str, Any]) -> Dict[str, Any]:
            await asyncio.sleep(0.1)  # Simulate processing
            return ResponseEnvelope.success(
                {"processed": True},
                message["id"],
            )

        listen_task = asyncio.create_task(
            transport.listen("127.0.0.1", 19994, handler)
        )
        await asyncio.sleep(0.5)

        try:
            # Create 5 concurrent requests
            tasks = []
            for i in range(5):
                hello = HelloMessage(
                    nonce_a=create_valid_nonce(),
                    agent_did="did:key:z123456789",
                    manifest_hash=create_valid_manifest_hash(),
                )

                request = RequestEnvelope.create(
                    method="handshake/hello",
                    params=hello.model_dump(),
                    request_id=f"hs-concurrent-{i}",
                )

                task = transport.send(
                    "http://127.0.0.1:19994/a2a/handshake",
                    request,
                    timeout=5.0,
                )
                tasks.append(task)

            # Send all concurrently
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            # Verify all succeeded
            assert len(responses) == 5
            for response in responses:
                assert not isinstance(response, Exception)
                assert response["jsonrpc"] == "2.0"
                assert "result" in response

        finally:
            listen_task.cancel()
            try:
                await listen_task
            except asyncio.CancelledError:
                pass
            await transport.close()

    @pytest.mark.asyncio
    async def test_06_jsonrpc_error_handling(self):
        """Test JSON-RPC error handling in handshake."""
        transport = HTTPTransport()

        # Server handler that returns error
        async def handler(message: Dict[str, Any]) -> Dict[str, Any]:
            return ResponseEnvelope.error(
                code=-32601,
                message="Method not found",
                request_id=message["id"],
            )

        listen_task = asyncio.create_task(
            transport.listen("127.0.0.1", 19995, handler)
        )
        await asyncio.sleep(0.5)

        try:
            request = RequestEnvelope.create(
                method="unknown/method",
                params={},
                request_id="hs-err-001",
            )

            # This should raise JSONRPCError
            with pytest.raises(Exception):  # JSONRPCError
                await transport.send(
                    "http://127.0.0.1:19995/a2a/handshake",
                    request,
                    timeout=5.0,
                )

        finally:
            listen_task.cancel()
            try:
                await listen_task
            except asyncio.CancelledError:
                pass
            await transport.close()

    @pytest.mark.asyncio
    async def test_07_handshake_message_validation(self):
        """Test strict validation of all handshake message types."""
        transport = HTTPTransport()

        async def handler(message: Dict[str, Any]) -> Dict[str, Any]:
            return ResponseEnvelope.success({}, message["id"])

        listen_task = asyncio.create_task(
            transport.listen("127.0.0.1", 19996, handler)
        )
        await asyncio.sleep(0.5)

        try:
            # Test 1: Valid HELLO
            hello = HelloMessage(
                nonce_a=create_valid_nonce(),
                agent_did="did:key:z123456789",
                manifest_hash=create_valid_manifest_hash(),
            )
            assert hello.message_type == MessageType.HELLO

            # Test 2: Valid CHALLENGE
            challenge = ChallengeMessage(
                nonce_b=create_valid_nonce(),
                policy_hash=create_valid_policy_hash(),
                public_keys=[{"key": "test_key", "alg": "EdDSA"}],
            )
            assert challenge.message_type == MessageType.CHALLENGE

            # Test 3: Valid PROOF
            proof = ProofMessage(
                nonce_a=create_valid_nonce(),
                nonce_b=create_valid_nonce(),
                proof="header.payload.signature",
            )
            assert proof.message_type == MessageType.PROOF

            # Test 4: Valid POLICY
            policy = PolicyMessage(
                policy={"rate_limit": 100},
                signature="sig.ature.value",
            )
            assert policy.message_type == MessageType.POLICY

            # Test 5: Valid ACCEPT_POLICY
            accept_policy = AcceptPolicyMessage(
                policy_hash=create_valid_policy_hash(),
                commitment="commit.ment.value",
            )
            assert accept_policy.message_type == MessageType.ACCEPT_POLICY

            # Test 6: Valid SESSION
            session = SessionMessage(
                session_id="session-123456789",
                expires_at=int(time.time()) + 3600,
                signature="session.sig.value",
            )
            assert session.message_type == MessageType.SESSION

        finally:
            listen_task.cancel()
            try:
                await listen_task
            except asyncio.CancelledError:
                pass
            await transport.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
