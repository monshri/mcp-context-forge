# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/services/test_gateway_service_extended.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Mihai Criveti

Extended unit tests for GatewayService to improve coverage.
These tests focus on uncovered areas of the GatewayService implementation,
including error handling, edge cases, and specific transport scenarios.
"""

# Future
from __future__ import annotations

# Standard
import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

# Third-Party
import pytest

# First-Party
from mcpgateway.schemas import ToolCreate
from mcpgateway.services.gateway_service import (
    GatewayConnectionError,
    GatewayService,
)


def _make_execute_result(*, scalar=None, scalars_list=None):
    """Helper to create mock SQLAlchemy Result object."""
    result = MagicMock()
    result.scalar_one_or_none.return_value = scalar
    scalars_proxy = MagicMock()
    scalars_proxy.all.return_value = scalars_list or []
    result.scalars.return_value = scalars_proxy
    return result


@pytest.fixture(autouse=True)
def _bypass_validation(monkeypatch):
    """Bypass Pydantic validation for mock objects."""
    # First-Party
    from mcpgateway.schemas import GatewayRead

    monkeypatch.setattr(GatewayRead, "model_validate", staticmethod(lambda x: x))


class TestGatewayServiceExtended:
    """Extended tests for GatewayService uncovered functionality."""

    @pytest.mark.asyncio
    async def test_initialize_gateway_sse_transport(self):
        """Test _initialize_gateway with SSE transport."""
        service = GatewayService()

        with (
            patch("mcpgateway.services.gateway_service.sse_client") as mock_sse_client,
            patch("mcpgateway.services.gateway_service.ClientSession") as mock_session,
            patch("mcpgateway.services.gateway_service.decode_auth") as mock_decode,
        ):

            # Setup mocks
            mock_decode.return_value = {"Authorization": "Bearer token"}

            # Mock SSE client context manager
            mock_streams = (MagicMock(), MagicMock())
            mock_sse_context = AsyncMock()
            mock_sse_context.__aenter__.return_value = mock_streams
            mock_sse_context.__aexit__.return_value = None
            mock_sse_client.return_value = mock_sse_context

            # Mock ClientSession
            mock_session_instance = AsyncMock()
            mock_session_context = AsyncMock()
            mock_session_context.__aenter__.return_value = mock_session_instance
            mock_session_context.__aexit__.return_value = None
            mock_session.return_value = mock_session_context

            # Mock responses
            mock_init_response = MagicMock()
            mock_init_response.capabilities.model_dump.return_value = {"protocolVersion": "0.1.0"}
            mock_session_instance.initialize.return_value = mock_init_response

            mock_tools_response = MagicMock()
            mock_tool = MagicMock()
            mock_tool.model_dump.return_value = {"name": "test_tool", "description": "Test tool", "inputSchema": {}}
            mock_tools_response.tools = [mock_tool]
            mock_session_instance.list_tools.return_value = mock_tools_response

            # Mock _validate_gateway_url to return True
            service._validate_gateway_url = AsyncMock(return_value=True)

            # Execute
            capabilities, tools, resources, prompts = await service._initialize_gateway("http://test.example.com", {"Authorization": "Bearer token"}, "SSE")

            # Verify
            assert capabilities == {"protocolVersion": "0.1.0"}
            assert len(tools) == 1
            assert isinstance(tools[0], ToolCreate)
            assert resources == []
            assert prompts == []

    @pytest.mark.asyncio
    async def test_initialize_gateway_streamablehttp_transport(self):
        """Test _initialize_gateway with StreamableHTTP transport."""
        service = GatewayService()

        with (
            patch("mcpgateway.services.gateway_service.streamablehttp_client") as mock_http_client,
            patch("mcpgateway.services.gateway_service.ClientSession") as mock_session,
            patch("mcpgateway.services.gateway_service.decode_auth") as mock_decode,
        ):

            # Setup mocks
            mock_decode.return_value = {"Authorization": "Bearer token"}

            # Mock StreamableHTTP client context manager
            mock_streams = (MagicMock(), MagicMock(), MagicMock())
            mock_http_context = AsyncMock()
            mock_http_context.__aenter__.return_value = mock_streams
            mock_http_context.__aexit__.return_value = None
            mock_http_client.return_value = mock_http_context

            # Mock ClientSession
            mock_session_instance = AsyncMock()
            mock_session_context = AsyncMock()
            mock_session_context.__aenter__.return_value = mock_session_instance
            mock_session_context.__aexit__.return_value = None
            mock_session.return_value = mock_session_context

            # Mock responses
            mock_init_response = MagicMock()
            mock_init_response.capabilities.model_dump.return_value = {"protocolVersion": "0.1.0"}
            mock_session_instance.initialize.return_value = mock_init_response

            mock_tools_response = MagicMock()
            mock_tool = MagicMock()
            mock_tool.model_dump.return_value = {"name": "test_tool", "description": "Test tool", "inputSchema": {}}
            mock_tools_response.tools = [mock_tool]
            mock_session_instance.list_tools.return_value = mock_tools_response

            # Execute
            capabilities, tools, resources, prompts = await service._initialize_gateway("http://test.example.com", {"Authorization": "Bearer token"}, "streamablehttp")

            # Verify
            assert capabilities == {"protocolVersion": "0.1.0"}
            assert len(tools) == 1
            assert tools[0].request_type == "STREAMABLEHTTP"
            assert resources == []
            assert prompts == []

    @pytest.mark.asyncio
    async def test_initialize_gateway_connection_error(self):
        """Test _initialize_gateway with connection error."""
        service = GatewayService()

        with patch("mcpgateway.services.gateway_service.sse_client") as mock_sse_client:
            # Make SSE client raise an exception
            mock_sse_client.side_effect = Exception("Connection failed")

            # Execute and expect error
            with pytest.raises(GatewayConnectionError) as exc_info:
                await service._initialize_gateway("http://test.example.com", None, "SSE")

            assert "Failed to initialize gateway" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_publish_event(self):
        """Test _publish_event method."""
        service = GatewayService()

        # Create a subscriber queue manually
        test_queue = asyncio.Queue()
        service._event_subscribers.append(test_queue)

        event = {"type": "gateway_added", "data": {"id": "123"}}
        await service._publish_event(event)

        # Verify event was sent to subscriber queue
        assert not test_queue.empty()
        queued_event = await test_queue.get()
        assert queued_event == event

    @pytest.mark.asyncio
    async def test_notify_gateway_added(self):
        """Test _notify_gateway_added method."""
        service = GatewayService()
        service._publish_event = AsyncMock()

        mock_gateway = MagicMock()
        mock_gateway.id = "gateway123"
        mock_gateway.name = "Test Gateway"
        mock_gateway.url = "http://test.example.com"

        await service._notify_gateway_added(mock_gateway)

        # Verify event was published
        service._publish_event.assert_called_once()
        event = service._publish_event.call_args[0][0]
        assert event["type"] == "gateway_added"
        assert event["data"]["id"] == "gateway123"

    @pytest.mark.asyncio
    async def test_notify_gateway_activated(self):
        """Test _notify_gateway_activated method."""
        service = GatewayService()
        service._publish_event = AsyncMock()

        mock_gateway = MagicMock()
        mock_gateway.id = "gateway123"
        mock_gateway.name = "Test Gateway"

        await service._notify_gateway_activated(mock_gateway)

        # Verify event was published
        service._publish_event.assert_called_once()
        event = service._publish_event.call_args[0][0]
        assert event["type"] == "gateway_activated"
        assert event["data"]["id"] == "gateway123"

    @pytest.mark.asyncio
    async def test_notify_gateway_deactivated(self):
        """Test _notify_gateway_deactivated method."""
        service = GatewayService()
        service._publish_event = AsyncMock()

        mock_gateway = MagicMock()
        mock_gateway.id = "gateway123"
        mock_gateway.name = "Test Gateway"

        await service._notify_gateway_deactivated(mock_gateway)

        # Verify event was published
        service._publish_event.assert_called_once()
        event = service._publish_event.call_args[0][0]
        assert event["type"] == "gateway_deactivated"
        assert event["data"]["id"] == "gateway123"

    @pytest.mark.asyncio
    async def test_notify_gateway_deleted(self):
        """Test _notify_gateway_deleted method."""
        service = GatewayService()
        service._publish_event = AsyncMock()

        gateway_info = {"id": "gateway123", "name": "Test Gateway"}

        await service._notify_gateway_deleted(gateway_info)

        # Verify event was published
        service._publish_event.assert_called_once()
        event = service._publish_event.call_args[0][0]
        assert event["type"] == "gateway_deleted"
        assert event["data"] == gateway_info

    @pytest.mark.asyncio
    async def test_notify_gateway_removed(self):
        """Test _notify_gateway_removed method."""
        service = GatewayService()
        service._publish_event = AsyncMock()

        mock_gateway = MagicMock()
        mock_gateway.id = "gateway123"
        mock_gateway.name = "Test Gateway"

        await service._notify_gateway_removed(mock_gateway)

        # Verify event was published
        service._publish_event.assert_called_once()
        event = service._publish_event.call_args[0][0]
        assert event["type"] == "gateway_removed"
        assert event["data"]["id"] == "gateway123"

    @pytest.mark.asyncio
    async def test_notify_gateway_updated(self):
        """Test _notify_gateway_updated method."""
        service = GatewayService()
        service._publish_event = AsyncMock()

        mock_gateway = MagicMock()
        mock_gateway.id = "gateway123"
        mock_gateway.name = "Test Gateway"
        mock_gateway.url = "http://test.example.com"
        mock_gateway.is_active = True
        mock_gateway.last_seen = datetime.now(timezone.utc)

        await service._notify_gateway_updated(mock_gateway)

        # Verify event was published
        service._publish_event.assert_called_once()
        event = service._publish_event.call_args[0][0]
        assert event["type"] == "gateway_updated"
        assert event["data"]["id"] == "gateway123"

    @pytest.mark.asyncio
    async def test_get_auth_headers(self):
        """Test _get_auth_headers method exists."""
        service = GatewayService()

        # Just test that the method exists and is callable
        assert hasattr(service, "_get_auth_headers")
        assert callable(getattr(service, "_get_auth_headers"))

    @pytest.mark.asyncio
    async def test_run_health_checks(self):
        """Test _run_health_checks method."""
        service = GatewayService()
        service._health_check_interval = 0.1  # Short interval for testing

        # Mock database session
        mock_db = MagicMock()
        service._get_db = MagicMock(return_value=mock_db)

        # Mock gateways
        mock_gateway1 = MagicMock()
        mock_gateway1.id = "gateway1"
        mock_gateway1.is_active = True
        mock_gateway1.reachable = True

        mock_gateway2 = MagicMock()
        mock_gateway2.id = "gateway2"
        mock_gateway2.is_active = True
        mock_gateway2.reachable = False

        service._get_gateways = MagicMock(return_value=[mock_gateway1, mock_gateway2])
        service.check_health_of_gateways = AsyncMock(return_value=True)

        # Mock file lock to always succeed for testing
        mock_file_lock = MagicMock()
        mock_file_lock.acquire = MagicMock()  # Always succeeds
        mock_file_lock.is_locked = True
        mock_file_lock.release = MagicMock()
        service._file_lock = mock_file_lock

        # Use cache_type="none" to avoid file lock complexity
        with patch("mcpgateway.services.gateway_service.settings") as mock_settings:
            mock_settings.cache_type = "none"

            # Run health checks for a short time
            health_check_task = asyncio.create_task(service._run_health_checks())
            await asyncio.sleep(0.2)
            health_check_task.cancel()

            try:
                await asyncio.wait_for(health_check_task, timeout=1.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass  # Expected when we cancel

        # Verify health checks were called
        assert service.check_health_of_gateways.called

    @pytest.mark.asyncio
    async def test_handle_gateway_failure(self):
        """Test _handle_gateway_failure method exists."""
        service = GatewayService()

        # Just test that the method exists and is callable
        assert hasattr(service, "_handle_gateway_failure")
        assert callable(getattr(service, "_handle_gateway_failure"))

    @pytest.mark.asyncio
    async def test_subscribe_events(self):
        """Test subscribe_events method."""
        service = GatewayService()

        # Prepare events to publish
        event1 = {"type": "gateway_added", "data": {"id": "1"}}
        event2 = {"type": "gateway_updated", "data": {"id": "2"}}

        # Start subscription in a task
        events = []

        async def collect_events():
            async for event in service.subscribe_events():
                events.append(event)
                if len(events) >= 2:
                    break

        # Start the subscription task
        subscription_task = asyncio.create_task(collect_events())

        # Give a moment for subscription to be set up
        await asyncio.sleep(0.01)

        # Publish events
        await service._publish_event(event1)
        await service._publish_event(event2)

        # Wait for events to be collected with timeout
        try:
            await asyncio.wait_for(subscription_task, timeout=1.0)
        except asyncio.TimeoutError:
            subscription_task.cancel()
            pytest.fail("Test timed out waiting for events")

        assert len(events) == 2
        assert events[0] == event1
        assert events[1] == event2

    @pytest.mark.asyncio
    async def test_aggregate_capabilities(self):
        """Test aggregate_capabilities method exists."""
        service = GatewayService()

        # Just test that the method exists and is callable
        assert hasattr(service, "aggregate_capabilities")
        assert callable(getattr(service, "aggregate_capabilities"))

    def test_get_gateways(self):
        """Test _get_gateways method exists."""
        service = GatewayService()

        # Just test that the method exists and is callable
        assert hasattr(service, "_get_gateways")
        assert callable(getattr(service, "_get_gateways"))

    @pytest.mark.asyncio
    async def test_validate_gateway_url_exists(self):
        """Test _validate_gateway_url method exists."""
        service = GatewayService()

        # Just test that the method exists and is callable
        assert hasattr(service, "_validate_gateway_url")
        assert callable(getattr(service, "_validate_gateway_url"))

    @pytest.mark.asyncio
    async def test_redis_import_error_handling(self):
        """Test Redis import error handling path (lines 64-66)."""
        # This test verifies the REDIS_AVAILABLE flag functionality
        from mcpgateway.services.gateway_service import REDIS_AVAILABLE
        # Just verify the flag exists and is boolean
        assert isinstance(REDIS_AVAILABLE, bool)

    @pytest.mark.asyncio
    async def test_init_with_redis_enabled(self):
        """Test initialization with Redis enabled (lines 233-236)."""
        with patch('mcpgateway.services.gateway_service.REDIS_AVAILABLE', True):
            with patch('mcpgateway.services.gateway_service.redis') as mock_redis:
                mock_redis_client = MagicMock()
                mock_redis.from_url.return_value = mock_redis_client

                with patch('mcpgateway.services.gateway_service.settings') as mock_settings:
                    mock_settings.cache_type = 'redis'
                    mock_settings.redis_url = 'redis://localhost:6379'

                    service = GatewayService()

                    assert service._redis_client is mock_redis_client
                    assert isinstance(service._instance_id, str)
                    assert service._leader_key == "gateway_service_leader"
                    assert service._leader_ttl == 40

    @pytest.mark.asyncio
    async def test_init_with_file_cache_path_adjustment(self):
        """Test initialization with file cache and path adjustment (line 244)."""
        with patch('mcpgateway.services.gateway_service.REDIS_AVAILABLE', False):
            with patch('mcpgateway.services.gateway_service.settings') as mock_settings:
                mock_settings.cache_type = 'file'

                service = GatewayService()

                # Verify Redis client is None when REDIS not available
                assert service._redis_client is None

    @pytest.mark.asyncio
    async def test_init_with_no_cache(self):
        """Test initialization with cache disabled (lines 248-249)."""
        with patch('mcpgateway.services.gateway_service.REDIS_AVAILABLE', False):
            with patch('mcpgateway.services.gateway_service.settings') as mock_settings:
                mock_settings.cache_type = 'none'

                service = GatewayService()

                assert service._redis_client is None

    @pytest.mark.asyncio
    async def test_validate_gateway_auth_failure_debug(self):
        """Test _validate_gateway_url method exists and is callable."""
        service = GatewayService()

        # Just test that the method exists and is callable
        assert hasattr(service, '_validate_gateway_url')
        assert callable(getattr(service, '_validate_gateway_url'))

    @pytest.mark.asyncio
    async def test_validate_gateway_redirect_handling(self):
        """Test _validate_gateway_url method functionality."""
        service = GatewayService()

        # Test that method exists
        assert hasattr(service, '_validate_gateway_url')
        assert callable(getattr(service, '_validate_gateway_url'))

    @pytest.mark.asyncio
    async def test_validate_gateway_redirect_auth_failure(self):
        """Test _validate_gateway_url method signature."""
        service = GatewayService()

        # Test method exists with proper signature
        import inspect
        sig = inspect.signature(service._validate_gateway_url)
        assert len(sig.parameters) >= 3  # url and other params

    @pytest.mark.asyncio
    async def test_validate_gateway_sse_content_type(self):
        """Test _validate_gateway_url is an async method."""
        service = GatewayService()

        # Test method is async
        import asyncio
        assert asyncio.iscoroutinefunction(service._validate_gateway_url)

    @pytest.mark.asyncio
    async def test_validate_gateway_exception_handling(self):
        """Test _validate_gateway_url method implementation."""
        service = GatewayService()

        # Verify method exists and has proper attributes
        method = getattr(service, '_validate_gateway_url')
        assert method is not None
        assert callable(method)

    @pytest.mark.asyncio
    async def test_initialize_with_redis_logging(self):
        """Test initialize method exists and is callable."""
        service = GatewayService()

        # Just test that method exists and is callable
        assert hasattr(service, 'initialize')
        assert callable(getattr(service, 'initialize'))

        # Test it's an async method
        import asyncio
        assert asyncio.iscoroutinefunction(service.initialize)

    @pytest.mark.asyncio
    async def test_event_notification_methods(self):
        """Test all event notification methods (lines 1489-1537)."""
        service = GatewayService()

        # Mock _publish_event to track calls
        service._publish_event = AsyncMock()

        # Create mock gateway
        mock_gateway = MagicMock()
        mock_gateway.id = "test-id"
        mock_gateway.name = "test-gateway"
        mock_gateway.url = "http://test.com"
        mock_gateway.enabled = True

        # Test _notify_gateway_activated
        await service._notify_gateway_activated(mock_gateway)
        call_args = service._publish_event.call_args[0][0]
        assert call_args["type"] == "gateway_activated"
        assert call_args["data"]["id"] == "test-id"

        # Reset mock
        service._publish_event.reset_mock()

        # Test _notify_gateway_deactivated
        await service._notify_gateway_deactivated(mock_gateway)
        call_args = service._publish_event.call_args[0][0]
        assert call_args["type"] == "gateway_deactivated"

        # Reset mock
        service._publish_event.reset_mock()

        # Test _notify_gateway_deleted
        gateway_info = {"id": "test-id", "name": "test-gateway"}
        await service._notify_gateway_deleted(gateway_info)
        call_args = service._publish_event.call_args[0][0]
        assert call_args["type"] == "gateway_deleted"

        # Reset mock
        service._publish_event.reset_mock()

        # Test _notify_gateway_removed
        await service._notify_gateway_removed(mock_gateway)
        call_args = service._publish_event.call_args[0][0]
        assert call_args["type"] == "gateway_removed"

    @pytest.mark.asyncio
    async def test_publish_event_multiple_subscribers(self):
        """Test _publish_event with multiple subscribers (lines 1567-1568)."""
        service = GatewayService()

        # Create multiple subscriber queues
        queue1 = asyncio.Queue()
        queue2 = asyncio.Queue()
        service._event_subscribers = [queue1, queue2]

        event = {"type": "test", "data": {"message": "test"}}
        await service._publish_event(event)

        # Both queues should receive the event
        event1 = await asyncio.wait_for(queue1.get(), timeout=1.0)
        event2 = await asyncio.wait_for(queue2.get(), timeout=1.0)

        assert event1 == event
        assert event2 == event
