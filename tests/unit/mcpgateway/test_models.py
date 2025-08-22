# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/test_models.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Mihai Criveti

Tests for the MCP types module.
This module contains tests for the various MCP protocol type definitions
defined in the models.py module.
"""

# Standard
import json
import os

# Third-Party
from pydantic import ValidationError
import pytest

# First-Party
from mcpgateway.models import (
    ClientCapabilities,
    CreateMessageResult,
    ImageContent,
    Implementation,
    InitializeRequest,
    InitializeResult,
    ListResourceTemplatesResult,
    LogLevel,
    Message,
    ModelHint,
    ModelPreferences,
    PromptArgument,
    PromptReference,
    PromptResult,
    Resource,
    ResourceContent,
    ResourceReference,
    ResourceTemplate,
    Role,
    Root,
    SamplingMessage,
    ServerCapabilities,
    TextContent,
    Tool,
    ToolResult,
)

PROTOCOL_VERSION = os.getenv("PROTOCOL_VERSION", "2025-03-26")


class TestMCPTypes:
    """Test suite for MCP protocol types."""

    def test_role_enum(self):
        """Test Role enum values."""
        assert Role.ASSISTANT == "assistant"
        assert Role.USER == "user"

    def test_log_level_enum(self):
        """Test LogLevel enum values."""
        assert LogLevel.DEBUG == "debug"
        assert LogLevel.INFO == "info"
        assert LogLevel.NOTICE == "notice"
        assert LogLevel.WARNING == "warning"
        assert LogLevel.ERROR == "error"
        assert LogLevel.CRITICAL == "critical"
        assert LogLevel.ALERT == "alert"
        assert LogLevel.EMERGENCY == "emergency"

    def test_text_content(self):
        """Test TextContent model."""
        content = TextContent(type="text", text="Hello, world!")
        assert content.type == "text"
        assert content.text == "Hello, world!"

        # Test serialization
        json_str = content.model_dump_json()
        loaded = json.loads(json_str)
        assert loaded["type"] == "text"
        assert loaded["text"] == "Hello, world!"

        # Test missing required field
        with pytest.raises(ValidationError):
            TextContent(type="text")

    def test_image_content(self):
        """Test ImageContent model."""
        content = ImageContent(
            type="image",
            data=b"binary_image_data",
            mime_type="image/png",
        )
        assert content.type == "image"
        assert content.data == b"binary_image_data"
        assert content.mime_type == "image/png"

        # Test validation errors
        with pytest.raises(ValidationError):
            ImageContent(type="image", data=b"data")  # Missing mime_type

    def test_resource_content(self):
        """Test ResourceContent model."""
        # Text resource
        text_resource = ResourceContent(
            type="resource",
            uri="file:///example.txt",
            mime_type="text/plain",
            text="Example content",
        )
        assert text_resource.type == "resource"
        assert text_resource.uri == "file:///example.txt"
        assert text_resource.mime_type == "text/plain"
        assert text_resource.text == "Example content"
        assert text_resource.blob is None

        # Binary resource
        binary_resource = ResourceContent(
            type="resource",
            uri="file:///example.bin",
            mime_type="application/octet-stream",
            blob=b"binary_data",
        )
        assert binary_resource.type == "resource"
        assert binary_resource.uri == "file:///example.bin"
        assert binary_resource.mime_type == "application/octet-stream"
        assert binary_resource.text is None
        assert binary_resource.blob == b"binary_data"

        # Minimal required fields
        minimal = ResourceContent(
            type="resource",
            uri="file:///example",
        )
        assert minimal.type == "resource"
        assert minimal.uri == "file:///example"
        assert minimal.mime_type is None
        assert minimal.text is None
        assert minimal.blob is None

    def test_message(self):
        """Test Message model with different content types."""
        text_message = Message(
            role=Role.USER,
            content=TextContent(type="text", text="Hello, world!"),
        )
        assert text_message.role == Role.USER
        assert text_message.content.type == "text"
        assert text_message.content.text == "Hello, world!"

        image_message = Message(
            role=Role.ASSISTANT,
            content=ImageContent(
                type="image",
                data=b"binary_image_data",
                mime_type="image/png",
            ),
        )
        assert image_message.role == Role.ASSISTANT
        assert image_message.content.type == "image"
        assert image_message.content.data == b"binary_image_data"

    def test_prompt_argument(self):
        """Test PromptArgument model."""
        # Full argument
        arg = PromptArgument(
            name="language",
            description="Programming language",
            required=True,
        )
        assert arg.name == "language"
        assert arg.description == "Programming language"
        assert arg.required is True

        # Minimal argument
        minimal = PromptArgument(name="limit")
        assert minimal.name == "limit"
        assert minimal.description is None
        assert minimal.required is False

    def test_prompt_result(self):
        """Test PromptResult model."""
        result = PromptResult(
            messages=[
                Message(
                    role=Role.USER,
                    content=TextContent(type="text", text="Hello, world!"),
                ),
                Message(
                    role=Role.ASSISTANT,
                    content=TextContent(type="text", text="Hi there!"),
                ),
            ],
            description="Example prompt result",
        )
        assert len(result.messages) == 2
        assert result.messages[0].role == Role.USER
        assert result.messages[1].role == Role.ASSISTANT
        assert result.description == "Example prompt result"

        # Test with minimal fields
        minimal = PromptResult(
            messages=[
                Message(
                    role=Role.USER,
                    content=TextContent(type="text", text="Query"),
                ),
            ],
        )
        assert len(minimal.messages) == 1
        assert minimal.description is None

    def test_tool_result(self):
        """Test ToolResult model."""
        result = ToolResult(
            content=[
                TextContent(type="text", text="Result data"),
                ImageContent(
                    type="image",
                    data=b"image_data",
                    mime_type="image/jpeg",
                ),
            ],
            is_error=False,
        )
        assert len(result.content) == 2
        assert result.content[0].type == "text"
        assert result.content[1].type == "image"
        assert result.is_error is False

        # Test error result
        error_result = ToolResult(
            content=[TextContent(type="text", text="Error message")],
            is_error=True,
        )
        assert len(error_result.content) == 1
        assert error_result.is_error is True

    def test_resource(self):
        """Test Resource model."""
        resource = Resource(
            uri="file:///example.txt",
            name="Example Resource",
            description="An example resource",
            mime_type="text/plain",
            size=1024,
        )
        assert resource.uri == "file:///example.txt"
        assert resource.name == "Example Resource"
        assert resource.description == "An example resource"
        assert resource.mime_type == "text/plain"
        assert resource.size == 1024

        # Test minimal fields
        minimal = Resource(
            uri="file:///example.bin",
            name="Minimal Example",
        )
        assert minimal.uri == "file:///example.bin"
        assert minimal.name == "Minimal Example"
        assert minimal.description is None
        assert minimal.mime_type is None
        assert minimal.size is None

    def test_resource_template(self):
        """Test ResourceTemplate model."""
        template = ResourceTemplate(
            uri_template="file:///data/{user}/{file}",
            name="User Data Template",
            description="Template for user data files",
            mime_type="application/octet-stream",
        )
        assert template.uri_template == "file:///data/{user}/{file}"
        assert template.name == "User Data Template"
        assert template.description == "Template for user data files"
        assert template.mime_type == "application/octet-stream"

        # Test minimal fields
        minimal = ResourceTemplate(
            uri_template="file:///logs/{date}.log",
            name="Log Template",
        )
        assert minimal.uri_template == "file:///logs/{date}.log"
        assert minimal.name == "Log Template"
        assert minimal.description is None
        assert minimal.mime_type is None

    def test_list_resource_templates_result(self):
        """Test ListResourceTemplatesResult model."""
        result = ListResourceTemplatesResult(
            _meta={"version": "1.0"},
            next_cursor="abc123",
            resource_templates=[
                ResourceTemplate(
                    uri_template="file:///data/{user}/{file}",
                    name="User Data Template",
                ),
                ResourceTemplate(
                    uri_template="file:///logs/{date}.log",
                    name="Log Template",
                ),
            ],
        )
        assert result.meta == {"version": "1.0"}
        assert result.next_cursor == "abc123"
        assert len(result.resource_templates) == 2
        assert result.resource_templates[0].name == "User Data Template"
        assert result.resource_templates[1].name == "Log Template"

        # Test minimal fields
        minimal = ListResourceTemplatesResult(
            resource_templates=[
                ResourceTemplate(
                    uri_template="file:///data/{file}",
                    name="Simple Template",
                ),
            ],
        )
        assert minimal.meta is None
        assert minimal.next_cursor is None
        assert len(minimal.resource_templates) == 1

    def test_root(self):
        """Test Root model."""
        root = Root(
            uri="file:///data",
            name="Data Directory",
        )
        assert root.uri == "file:///data"
        assert root.name == "Data Directory"

        # Test minimal fields
        minimal = Root(uri="file:///logs")
        assert minimal.uri == "file:///logs"
        assert minimal.name is None

    def test_implementation(self):
        """Test Implementation model."""
        impl = Implementation(name="Test Gateway", version="1.0.0")
        assert impl.name == "Test Gateway"
        assert impl.version == "1.0.0"

    def test_model_hint(self):
        """Test ModelHint model."""
        hint = ModelHint(name="gpt-4")
        assert hint.name == "gpt-4"

        # Test empty hint
        empty = ModelHint()
        assert empty.name is None

    def test_model_preferences(self):
        """Test ModelPreferences model."""
        prefs = ModelPreferences(
            cost_priority=0.8,
            speed_priority=0.5,
            intelligence_priority=0.2,
            hints=[ModelHint(name="claude-3")],
        )
        assert prefs.cost_priority == 0.8
        assert prefs.speed_priority == 0.5
        assert prefs.intelligence_priority == 0.2
        assert len(prefs.hints) == 1
        assert prefs.hints[0].name == "claude-3"

        # Test minimal fields
        minimal = ModelPreferences(
            cost_priority=0.5,
            speed_priority=0.5,
            intelligence_priority=0.5,
        )
        assert minimal.cost_priority == 0.5
        assert minimal.speed_priority == 0.5
        assert minimal.intelligence_priority == 0.5
        assert len(minimal.hints) == 0

        # Test validation (priorities must be between 0 and 1)
        with pytest.raises(ValidationError):
            ModelPreferences(
                cost_priority=1.5,  # Invalid: > 1
                speed_priority=0.5,
                intelligence_priority=0.5,
            )

    def test_client_capabilities(self):
        """Test ClientCapabilities model."""
        caps = ClientCapabilities(
            roots={"listChanged": True},
            sampling={"supports_temperature": True},
            experimental={"feature": {"enabled": True}},
        )
        assert caps.roots == {"listChanged": True}
        assert caps.sampling == {"supports_temperature": True}
        assert caps.experimental == {"feature": {"enabled": True}}

        # Test minimal fields
        minimal = ClientCapabilities()
        assert minimal.roots is None
        assert minimal.sampling is None
        assert minimal.experimental is None

    def test_server_capabilities(self):
        """Test ServerCapabilities model."""
        caps = ServerCapabilities(
            prompts={"listChanged": True},
            resources={"subscribe": True, "listChanged": True},
            tools={"listChanged": True},
            logging={"setLevel": True},
            experimental={"feature": {"enabled": True}},
        )
        assert caps.prompts == {"listChanged": True}
        assert caps.resources == {"subscribe": True, "listChanged": True}
        assert caps.tools == {"listChanged": True}
        assert caps.logging == {"setLevel": True}
        assert caps.experimental == {"feature": {"enabled": True}}

        # Test minimal fields
        minimal = ServerCapabilities()
        assert minimal.prompts is None
        assert minimal.resources is None
        assert minimal.tools is None
        assert minimal.logging is None
        assert minimal.experimental is None

    def test_initialize_request(self):
        """Test InitializeRequest model."""
        request = InitializeRequest(
            protocol_version=PROTOCOL_VERSION,
            capabilities=ClientCapabilities(roots={"listChanged": True}),
            client_info=Implementation(name="Test Client", version="1.0.0"),
        )
        assert request.protocol_version == PROTOCOL_VERSION
        assert request.capabilities.roots == {"listChanged": True}
        assert request.client_info.name == "Test Client"
        assert request.client_info.version == "1.0.0"

        # Test with field aliases
        dict_data = {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"roots": {"listChanged": True}},
            "clientInfo": {"name": "Test Client", "version": "1.0.0"},
        }
        from_dict = InitializeRequest.model_validate(dict_data)
        assert from_dict.protocol_version == PROTOCOL_VERSION
        assert from_dict.capabilities.roots == {"listChanged": True}
        assert from_dict.client_info.name == "Test Client"

    def test_initialize_result(self):
        """Test InitializeResult model."""
        result = InitializeResult(
            protocol_version=PROTOCOL_VERSION,
            capabilities=ServerCapabilities(
                prompts={"listChanged": True},
                resources={"subscribe": True},
                tools={"listChanged": True},
            ),
            server_info=Implementation(name="Test Server", version="1.0.0"),
            instructions="Example instructions for the client.",
        )
        assert result.protocol_version == PROTOCOL_VERSION
        assert result.capabilities.prompts == {"listChanged": True}
        assert result.capabilities.resources == {"subscribe": True}
        assert result.capabilities.tools == {"listChanged": True}
        assert result.server_info.name == "Test Server"
        assert result.server_info.version == "1.0.0"
        assert result.instructions == "Example instructions for the client."

        # Test with field aliases
        dict_data = {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "prompts": {"listChanged": True},
                "resources": {"subscribe": True},
                "tools": {"listChanged": True},
            },
            "serverInfo": {"name": "Test Server", "version": "1.0.0"},
        }
        from_dict = InitializeResult.model_validate(dict_data)
        assert from_dict.protocol_version == PROTOCOL_VERSION
        assert from_dict.capabilities.prompts == {"listChanged": True}
        assert from_dict.server_info.name == "Test Server"
        assert from_dict.instructions is None

    def test_sampling_message(self):
        """Test SamplingMessage model."""
        message = SamplingMessage(
            role=Role.USER,
            content=TextContent(type="text", text="Sample text"),
        )
        assert message.role == Role.USER
        assert message.content.type == "text"
        assert message.content.text == "Sample text"

    def test_create_message_result(self):
        """Test CreateMessageResult model."""
        result = CreateMessageResult(
            content=TextContent(type="text", text="Generated response"),
            model="claude-3",
            role=Role.ASSISTANT,
            stop_reason="maxTokens",
        )
        assert result.content.type == "text"
        assert result.content.text == "Generated response"
        assert result.model == "claude-3"
        assert result.role == Role.ASSISTANT
        assert result.stop_reason == "maxTokens"

        # Test minimal fields
        minimal = CreateMessageResult(
            content=TextContent(type="text", text="Response"),
            model="gpt-4",
            role=Role.ASSISTANT,
        )
        assert minimal.content.text == "Response"
        assert minimal.model == "gpt-4"
        assert minimal.role == Role.ASSISTANT
        assert minimal.stop_reason is None

    def test_prompt_reference(self):
        """Test PromptReference model."""
        ref = PromptReference(type="ref/prompt", name="example-prompt")
        assert ref.type == "ref/prompt"
        assert ref.name == "example-prompt"

    def test_resource_reference(self):
        """Test ResourceReference model."""
        ref = ResourceReference(type="ref/resource", uri="file:///example.txt")
        assert ref.type == "ref/resource"
        assert ref.uri == "file:///example.txt"

    def test_tool(self):
        """Test Tool model."""
        tool = Tool(
            name="example-tool",
            url="http://localhost:8000/tool",
            description="An example tool",
            integration_type="MCP",
            request_type="SSE",
            headers={"Content-Type": "application/json"},
            input_schema={"type": "object", "properties": {"query": {"type": "string"}}},
            auth_type="bearer",
            auth_token="example-token",
        )
        assert tool.name == "example-tool"
        assert str(tool.url) == "http://localhost:8000/tool"
        assert tool.description == "An example tool"
        assert tool.integration_type == "MCP"
        assert tool.request_type == "SSE"
        assert tool.headers == {"Content-Type": "application/json"}
        assert tool.input_schema == {"type": "object", "properties": {"query": {"type": "string"}}}
        assert tool.auth_type == "bearer"
        assert tool.auth_token == "example-token"

        # Test minimal fields
        minimal = Tool(
            name="minimal-tool",
            url="http://localhost:8000/minimal",
        )
        assert minimal.name == "minimal-tool"
        assert str(minimal.url) == "http://localhost:8000/minimal"
        assert minimal.description is None
        assert minimal.integration_type == "MCP"  # Default value
        assert minimal.request_type == "SSE"  # Default value
        assert minimal.headers == {}  # Default value
        assert minimal.input_schema == {"type": "object", "properties": {}}  # Default value
        assert minimal.auth_type is None
        assert minimal.auth_username is None
        assert minimal.auth_password is None
        assert minimal.auth_token is None
