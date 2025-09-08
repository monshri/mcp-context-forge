# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/plugins/framework/external/mcp/test_client_config.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Fred Araujo

Additional unit tests for ExternalPlugin client.
Tests for error conditions, edge cases, and uncovered code paths.
"""

# Standard
import os
from unittest.mock import AsyncMock, Mock, patch

# Third-Party
from mcp.types import CallToolResult
import pytest

# First-Party
from mcpgateway.models import Message, PromptResult, ResourceContent, Role, TextContent
from mcpgateway.plugins.framework import (
    ConfigLoader,
    GlobalContext,
    PluginContext,
    PromptPosthookPayload,
    PromptPrehookPayload,
    ResourcePostFetchPayload,
    ResourcePreFetchPayload,
    ToolPostInvokePayload,
    ToolPreInvokePayload,
)
from mcpgateway.plugins.framework.errors import PluginError
from mcpgateway.plugins.framework.external.mcp.client import ExternalPlugin


@pytest.mark.asyncio
async def test_initialize_missing_mcp_config():
    """Test initialize raises ValueError when mcp config is missing."""
    # Use a real config but temporarily remove mcp section
    config = ConfigLoader.load_config("tests/unit/mcpgateway/plugins/fixtures/configs/valid_stdio_external_plugin.yaml")
    plugin_config = config.plugins[0]

    # Create plugin and temporarily set mcp to None
    plugin = ExternalPlugin(plugin_config)
    plugin._config.mcp = None

    with pytest.raises(PluginError, match="The mcp section must be defined for external plugin"):
        await plugin.initialize()


@pytest.mark.asyncio
async def test_initialize_stdio_non_python_script():
    """Test initialize raises ValueError for non-Python stdio script."""
    config = ConfigLoader.load_config("tests/unit/mcpgateway/plugins/fixtures/configs/valid_stdio_external_plugin.yaml")
    plugin_config = config.plugins[0]
    plugin = ExternalPlugin(plugin_config)

    # Mock the script path to be non-Python
    plugin._config.mcp.script = "/path/to/script.sh"

    with pytest.raises(PluginError, match="Server script must be a .py file"):
        await plugin.initialize()


@pytest.mark.asyncio
async def test_initialize_config_retrieval_failure():
    """Test initialize raises ValueError when plugin config retrieval fails."""
    os.environ["PLUGINS_CONFIG_PATH"] = "tests/unit/mcpgateway/plugins/fixtures/configs/valid_multiple_plugins_filter.yaml"
    os.environ["PYTHONPATH"] = "."

    config = ConfigLoader.load_config("tests/unit/mcpgateway/plugins/fixtures/configs/valid_stdio_external_plugin.yaml")
    plugin_config = config.plugins[0]
    plugin = ExternalPlugin(plugin_config)

    # Mock stdio connection to succeed but config retrieval to fail
    mock_stdio = Mock()
    mock_write = Mock()
    mock_session = AsyncMock()
    mock_session.initialize = AsyncMock()
    mock_session.list_tools = AsyncMock()
    mock_session.list_tools.return_value.tools = []

    # Mock get_plugin_config to return empty content (failure)
    mock_session.call_tool = AsyncMock()
    mock_session.call_tool.return_value = CallToolResult(content=[])

    with patch('mcpgateway.plugins.framework.external.mcp.client.stdio_client') as mock_stdio_client, \
         patch('mcpgateway.plugins.framework.external.mcp.client.ClientSession', return_value=mock_session):

        mock_stdio_client.return_value.__aenter__ = AsyncMock(return_value=(mock_stdio, mock_write))
        mock_stdio_client.return_value.__aexit__ = AsyncMock(return_value=False)

        with pytest.raises(PluginError, match="Unable to retrieve configuration for external plugin"):
            await plugin.initialize()

    # Cleanup
    if "PLUGINS_CONFIG_PATH" in os.environ:
        del os.environ["PLUGINS_CONFIG_PATH"]
    if "PYTHONPATH" in os.environ:
        del os.environ["PYTHONPATH"]


@pytest.mark.asyncio
async def test_hook_methods_empty_content():
    """Test hook methods raise PluginError when content is empty."""
    config = ConfigLoader.load_config("tests/unit/mcpgateway/plugins/fixtures/configs/valid_stdio_external_plugin.yaml")
    plugin_config = config.plugins[0]
    plugin = ExternalPlugin(plugin_config)

    # Set up session mock
    mock_session = AsyncMock()
    plugin._session = mock_session

    # Mock empty content response
    mock_session.call_tool = AsyncMock()
    mock_session.call_tool.return_value = CallToolResult(content=[])

    context = PluginContext(global_context=GlobalContext(request_id="test", server_id="test"))

    # Test prompt_pre_fetch with empty content - should raise PluginError
    payload = PromptPrehookPayload(name="test", args={})
    with pytest.raises(PluginError):
        await plugin.prompt_pre_fetch(payload, context)

    # Test prompt_post_fetch with empty content - should raise PluginError
    message = Message(content=TextContent(type="text", text="test"), role=Role.USER)
    prompt_result = PromptResult(messages=[message])
    payload = PromptPosthookPayload(name="test", result=prompt_result)
    with pytest.raises(PluginError):
        await plugin.prompt_post_fetch(payload, context)

    # Test tool_pre_invoke with empty content - should raise PluginError
    payload = ToolPreInvokePayload(name="test", args={})
    with pytest.raises(PluginError):
        await plugin.tool_pre_invoke(payload, context)

    # Test tool_post_invoke with empty content - should raise PluginError
    payload = ToolPostInvokePayload(name="test", result={})
    with pytest.raises(PluginError):
        await plugin.tool_post_invoke(payload, context)

    # Test resource_pre_fetch with empty content - should raise PluginError
    payload = ResourcePreFetchPayload(uri="file://test.txt")
    with pytest.raises(PluginError):
        await plugin.resource_pre_fetch(payload, context)

    # Test resource_post_fetch with empty content - should raise PluginError
    resource_content = ResourceContent(type="resource", uri="file://test.txt", text="content")
    payload = ResourcePostFetchPayload(uri="file://test.txt", content=resource_content)
    with pytest.raises(PluginError):
        await plugin.resource_post_fetch(payload, context)

    await plugin.shutdown()


@pytest.mark.asyncio
async def test_get_plugin_config_no_content():
    """Test __get_plugin_config returns None when no content."""
    config = ConfigLoader.load_config("tests/unit/mcpgateway/plugins/fixtures/configs/valid_stdio_external_plugin.yaml")
    plugin_config = config.plugins[0]
    plugin = ExternalPlugin(plugin_config)

    # Set up session mock
    mock_session = AsyncMock()
    plugin._session = mock_session

    # Mock empty content response
    mock_session.call_tool = AsyncMock()
    mock_session.call_tool.return_value = CallToolResult(content=[])

    result = await plugin._ExternalPlugin__get_plugin_config()
    assert result is None

    await plugin.shutdown()


@pytest.mark.asyncio
async def test_shutdown():
    """Test shutdown method calls exit_stack.aclose()."""
    config = ConfigLoader.load_config("tests/unit/mcpgateway/plugins/fixtures/configs/valid_stdio_external_plugin.yaml")
    plugin_config = config.plugins[0]
    plugin = ExternalPlugin(plugin_config)

    # Mock the exit stack
    mock_exit_stack = AsyncMock()
    plugin._exit_stack = mock_exit_stack

    await plugin.shutdown()
    mock_exit_stack.aclose.assert_called_once()
