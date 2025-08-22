# Plugin Framework

!!! success "Production Ready"
    The plugin framework is **production ready** with comprehensive hook coverage, robust error handling, and battle-tested implementations. Supports both self-contained and external service plugins.

## Overview

The MCP Context Forge Plugin Framework provides a comprehensive, production-grade system for extending gateway functionality through pre/post processing hooks at various points in the MCP request lifecycle. The framework supports both high-performance self-contained plugins and sophisticated external AI service integrations.

### Key Capabilities

- **AI Safety Middleware** - Integration with LlamaGuard, OpenAI Moderation, custom ML models
- **Content Security** - PII detection and masking, input validation, output sanitization
- **Policy Enforcement** - Business rules, compliance checking, audit trails
- **Performance Protection** - Timeout handling, resource limits, graceful degradation
- **Operational Excellence** - Hot configuration reload, health monitoring, detailed metrics
- **Enterprise Features** - Multi-tenant isolation, conditional execution, sophisticated context management

## Architecture

The plugin framework implements a **hybrid architecture** supporting both self-contained and external service integrations:

### Self-Contained Plugins
- **In-Process Execution:** Written in Python, run directly within the gateway process
- **High Performance:** Sub-millisecond latency, no network overhead
- **Direct Access:** Full access to gateway internals and context
- **Use Cases:** PII filtering, regex transformations, input validation, simple business rules
- **Examples:** `PIIFilterPlugin`, `SearchReplacePlugin`, `DenyListPlugin`

### External Service Plugins
- **Microservice Integration:** Call external AI safety services via HTTP/gRPC/MCP
- **Enterprise AI Support:** LlamaGuard, OpenAI Moderation, custom ML models
- **Authentication Support:** Bearer tokens, API keys, mutual TLS, custom headers
- **Scalable Architecture:** Services can be deployed independently, auto-scaled
- **Use Cases:** Advanced AI safety, complex ML inference, enterprise policy engines
- **Examples:** LlamaGuard integration, OpenAI Moderation, HashiCorp Vault, OPA

### Unified Plugin Interface

Both plugin types implement the same interface, enabling seamless switching between deployment models:

```python
class Plugin:
    async def prompt_pre_fetch(self, payload, context) -> PluginResult
    async def tool_pre_invoke(self, payload, context) -> PluginResult
    # ... unified interface for all hook points
```

## Enabling Plugins

### 1. Environment Configuration

Enable the plugin framework in your `.env` file:

```bash
# Enable plugin framework
PLUGINS_ENABLED=true

# Optional: Custom plugin config path
PLUGIN_CONFIG_FILE=plugins/config.yaml
```

### 2. Plugin Configuration

The plugin configuration file is used to configure a set of plugins to run a
set of hook points throughout the MCP Context Forge.  An example configuration
is below.  It contains two main sections: `plugins` and `plugin_settings`.

Create or modify `plugins/config.yaml`:

```yaml
# Main plugin configuration
plugins:
  - name: "ContentFilter"
    kind: "plugins.native.content_filter.ContentFilterPlugin"
    description: "Filters inappropriate content"
    version: "1.0"
    author: "Your Team"
    hooks: ["prompt_pre_fetch", "prompt_post_fetch"]
    tags: ["security", "filter"]
    mode: "enforce"  # enforce | permissive | disabled
    priority: 100    # Lower number = higher priority
    conditions:
      - prompts: ["customer_chat", "support_bot"]
        server_ids: []  # Apply to all servers
        tenant_ids: []  # Apply to all tenants
    config:
      # Plugin-specific configuration
      block_patterns: ["ssn", "credit_card"]
      mask_char: "*"

# Global plugin settings
plugin_settings:
  parallel_execution_within_band: false
  plugin_timeout: 30
  fail_on_plugin_error: false
  enable_plugin_api: true
  plugin_health_check_interval: 60
```

The `plugins` section lists the set of configured plugins that will be loaded
by the Context Forge at startup.  Each plugin contains a set of standard configurations,
and then a `config` section designed for plugin specific configurations. The attributes
are defined as follows:

| Attribute | Description | Example Value |
|-----------|-------------|---------------|
| **name**  | A unique name for the plugin. | MyFirstPlugin |
| **kind**  | A fully qualified string representing the plugin python object. | plugins.native.content_filter.ContentFilterPlugin |
| **description** | The description of the plugin configuration. | A plugin for replacing bad words. |
| **version** | The version of the plugin configuration. | 0.1 |
| **author** | The team that wrote the plugin. | MCP Context Forge |
| **hooks** | A list of hooks for which the plugin will be executed. Supported hooks: "prompt_pre_fetch", "prompt_post_fetch", "tool_pre_invoke", "tool_post_invoke", "resource_pre_fetch", "resource_post_fetch"  | ["prompt_pre_fetch", "prompt_post_fetch", "tool_pre_invoke", "tool_post_invoke", "resource_pre_fetch", "resource_post_fetch"] |
| **tags** | Descriptive keywords that make the configuration searchable. | ["security", "filter"] |
| **mode** | Mode of operation of the plugin. - enforce (stops during a violation), permissive (audits a violation but doesn't stop), disabled (disabled) | permissive |
| **priority** | The priority in which the plugin will run - 0 is higher priority | 100 |
| **conditions** | A list of conditions under which a plugin is run. See section on conditions.|  |
| **config** | Plugin specific configuration.  This is a dictionary and is passed to the plugin on initialization. |   |

The `plugin_settings` are as follows:

| Attribute | Description | Example Value |
|-----------|-------------|---------------|
| **parallel_execution_within_band** | Plugins in the same band are run in parallel (currently not implemented). | true or false |
| **plugin_timeout** | The time in seconds before stopping plugin execution (not implemented). | 30 |
| **fail_on_plugin_error** | Cause the execution of the task to fail if the plugin errors. | true or false |
| **plugin_health_check_interval** | Health check interval in seconds (not implemented). | 60 |


### 3. Execution Modes

Each plugin can operate in one of three modes:

| Mode | Description | Use Case |
|------|-------------|----------|
| **enforce** | Blocks requests on policy violations | Production guardrails |
| **permissive** | Logs violations but allows requests | Testing and monitoring |
| **disabled** | Plugin loaded but not executed | Temporary deactivation |

### 4. Priority and Execution Order

Plugins execute in priority order (ascending):

```yaml
# Execution order example
plugins:
  - name: "Authentication"
    priority: 10      # Runs first

  - name: "RateLimiter"
    priority: 50      # Runs second

  - name: "ContentFilter"
    priority: 100     # Runs third

  - name: "Logger"
    priority: 200     # Runs last
```

Plugins with the same priority may execute in parallel if `parallel_execution_within_band` is enabled.

### 5. Conditions of Execution

Users may only want plugins to be invoked on specific servers, tools, and prompts. To address this, a set of conditionals can be applied to a plugin. The attributes in a conditional combine together in as a set of `and` operations, while each attribute list item is `ored` with other items in the list.  The attributes are defined as follows:

| Attribute | Description
|-----------|------------|
| **server_ids** | The list of MCP servers on which the plugin will trigger |
| **tools** | The list of tools on which the plugin will be applied. |
| **prompts** | The list of prompts on which the plugin will be applied. |
| **resources** | The list of resource URIs on which the plugin will be applied. |
| **user_patterns** | The list of users on which the plugin will be applied. |
| **content_types** | The list of content types on which the plugin will trigger. |

## Available Hooks

The plugin framework provides comprehensive hook coverage across the entire MCP request lifecycle:

### Production Hooks (Implemented)

| Hook | Execution Point | Use Cases | Payload Type |
|------|----------------|-----------|--------------|
| `prompt_pre_fetch` | Before prompt template retrieval | Argument validation, PII scanning, input sanitization | `PromptPrehookPayload` |
| `prompt_post_fetch` | After prompt template rendering | Content filtering, output transformation, safety checks | `PromptPosthookPayload` |
| `tool_pre_invoke` | Before tool execution | Authorization, argument validation, dangerous operation blocking | `ToolPreInvokePayload` |
| `tool_post_invoke` | After tool execution | Result filtering, PII masking, audit logging, response transformation | `ToolPostInvokePayload` |
| `resource_pre_fetch` | Before resource fetching | URI validation, protocol checking, metadata injection | `ResourcePreFetchPayload` |
| `resource_post_fetch` | After resource content retrieval | Content filtering, size validation, sensitive data redaction | `ResourcePostFetchPayload` |

### Planned Hooks (Roadmap)

| Hook | Purpose | Expected Release |
|------|---------|-----------------|
| `server_pre_register` | Server attestation and validation before admission | v0.7.0 |
| `server_post_register` | Post-registration processing and setup | v0.7.0 |
| `auth_pre_check` | Custom authentication logic integration | v0.7.0 |
| `auth_post_check` | Post-authentication processing and enrichment | v0.7.0 |
| `federation_pre_sync` | Gateway federation validation and filtering | v0.8.0 |
| `federation_post_sync` | Post-federation data processing and reconciliation | v0.8.0 |

### Tool Hooks Details

The tool hooks enable plugins to intercept and modify tool invocations:

- **`tool_pre_invoke`**: Receives the tool name and arguments before execution. Can modify arguments or block the invocation entirely.
- **`tool_post_invoke`**: Receives the tool result after execution. Can modify the result or block it from being returned.

Example use cases:
- PII detection and masking in tool inputs/outputs
- Rate limiting specific tools
- Audit logging of tool usage
- Input validation and sanitization
- Output filtering and transformation

### Resource Hooks Details

The resource hooks enable plugins to intercept and modify resource fetching:

- **`resource_pre_fetch`**: Receives the resource URI and metadata before fetching. Can modify the URI, add metadata, or block the fetch entirely.
- **`resource_post_fetch`**: Receives the resource content after fetching. Can modify the content, redact sensitive information, or block it from being returned.

Example use cases:
- Protocol validation (block non-HTTPS resources)
- Domain blocklisting/allowlisting
- Content size limiting
- Sensitive data redaction
- Content transformation and filtering
- Resource caching metadata

Planned hooks (not yet implemented):

- `server_pre_register` / `server_post_register` - Server validation
- `auth_pre_check` / `auth_post_check` - Custom authentication
- `federation_pre_sync` / `federation_post_sync` - Gateway federation

## Writing Plugins

### Plugin Structure

```python
from mcpgateway.plugins.framework import (
    Plugin,
    PluginConfig,
    PluginContext,
    PromptPrehookPayload,
    PromptPrehookResult,
    PromptPosthookPayload,
    PromptPosthookResult,
    ToolPreInvokePayload,
    ToolPreInvokeResult,
    ToolPostInvokePayload,
    ToolPostInvokeResult,
    ResourcePreFetchPayload,
    ResourcePreFetchResult,
    ResourcePostFetchPayload,
    ResourcePostFetchResult
)

class MyPlugin(Plugin):
    """Example plugin implementation."""

    def __init__(self, config: PluginConfig):
        super().__init__(config)
        # Initialize plugin-specific configuration
        self.my_setting = config.config.get("my_setting", "default")

    async def prompt_pre_fetch(
        self,
        payload: PromptPrehookPayload,
        context: PluginContext
    ) -> PromptPrehookResult:
        """Process prompt before retrieval."""

        # Access prompt name and arguments
        prompt_name = payload.name
        args = payload.args

        # Example: Block requests with forbidden words
        if "forbidden" in str(args.values()).lower():
            return PromptPrehookResult(
                continue_processing=False,
                violation=PluginViolation(
                    plugin_name=self.name,
                    description="Forbidden content detected",
                    violation_code="FORBIDDEN_CONTENT",
                    details={"found_in": "arguments"}
                )
            )

        # Example: Modify arguments
        if "transform_me" in args:
            args["transform_me"] = args["transform_me"].upper()
            return PromptPrehookResult(
                modified_payload=PromptPrehookPayload(prompt_name, args)
            )

        # Allow request to continue unmodified
        return PromptPrehookResult()

    async def prompt_post_fetch(
        self,
        payload: PromptPosthookPayload,
        context: PluginContext
    ) -> PromptPosthookResult:
        """Process prompt after rendering."""

        # Access rendered prompt
        prompt_result = payload.result

        # Example: Add metadata to context
        context.metadata["processed_by"] = self.name

        # Example: Modify response
        for message in prompt_result.messages:
            message.content.text = message.content.text.replace(
                "old_text", "new_text"
            )

        return PromptPosthookResult(
            modified_payload=payload
        )

    async def tool_pre_invoke(
        self,
        payload: ToolPreInvokePayload,
        context: PluginContext
    ) -> ToolPreInvokeResult:
        """Process tool before invocation."""

        # Access tool name and arguments
        tool_name = payload.name
        args = payload.args

        # Example: Block dangerous operations
        if tool_name == "file_delete" and "system" in str(args):
            return ToolPreInvokeResult(
                continue_processing=False,
                violation=PluginViolation(
                    plugin_name=self.name,
                    description="Dangerous operation blocked",
                    violation_code="DANGEROUS_OP",
                    details={"tool": tool_name}
                )
            )

        # Example: Modify arguments
        if "sanitize_me" in args:
            args["sanitize_me"] = self.sanitize_input(args["sanitize_me"])
            return ToolPreInvokeResult(
                modified_payload=ToolPreInvokePayload(tool_name, args)
            )

        return ToolPreInvokeResult()

    async def tool_post_invoke(
        self,
        payload: ToolPostInvokePayload,
        context: PluginContext
    ) -> ToolPostInvokeResult:
        """Process tool after invocation."""

        # Access tool result
        tool_name = payload.name
        result = payload.result

        # Example: Filter sensitive data from results
        if isinstance(result, dict) and "sensitive_data" in result:
            result["sensitive_data"] = "[REDACTED]"
            return ToolPostInvokeResult(
                modified_payload=ToolPostInvokePayload(tool_name, result)
            )

        # Example: Add audit metadata
        context.metadata["tool_executed"] = tool_name
        context.metadata["execution_time"] = time.time()

        return ToolPostInvokeResult()

    async def resource_pre_fetch(
        self,
        payload: ResourcePreFetchPayload,
        context: PluginContext
    ) -> ResourcePreFetchResult:
        """Process resource before fetching."""

        # Access resource URI and metadata
        uri = payload.uri
        metadata = payload.metadata

        # Example: Block certain protocols
        from urllib.parse import urlparse
        parsed = urlparse(uri)
        if parsed.scheme not in ["http", "https", "file"]:
            return ResourcePreFetchResult(
                continue_processing=False,
                violation=PluginViolation(
                    plugin_name=self.name,
                    description=f"Protocol {parsed.scheme} not allowed",
                    violation_code="PROTOCOL_BLOCKED",
                    details={"uri": uri, "protocol": parsed.scheme}
                )
            )

        # Example: Add metadata
        metadata["validated_by"] = self.name
        return ResourcePreFetchResult(
            modified_payload=ResourcePreFetchPayload(uri, metadata)
        )

    async def resource_post_fetch(
        self,
        payload: ResourcePostFetchPayload,
        context: PluginContext
    ) -> ResourcePostFetchResult:
        """Process resource after fetching."""

        # Access resource content
        uri = payload.uri
        content = payload.content

        # Example: Redact sensitive patterns from text content
        if hasattr(content, 'text') and content.text:
            # Redact email addresses
            import re
            content.text = re.sub(
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                '[EMAIL_REDACTED]',
                content.text
            )

        return ResourcePostFetchResult(
            modified_payload=ResourcePostFetchPayload(uri, content)
        )

    async def shutdown(self):
        """Cleanup when plugin shuts down."""
        # Close connections, save state, etc.
        pass
```

### Plugin Context and State

Plugins can maintain state between pre/post hooks:

```python
async def prompt_pre_fetch(self, payload, context):
    # Store state for later use
    context.set_state("request_time", time.time())
    context.set_state("original_args", payload.args.copy())

    return PromptPrehookResult()

async def prompt_post_fetch(self, payload, context):
    # Retrieve state from pre-hook
    elapsed = time.time() - context.get_state("request_time", 0)
    original = context.get_state("original_args", {})

    # Add timing metadata
    context.metadata["processing_time_ms"] = elapsed * 1000

    return PromptPosthookResult()
```

### External Service Plugin Example

```python
class LLMGuardPlugin(Plugin):
    """Example external service integration."""

    def __init__(self, config: PluginConfig):
        super().__init__(config)
        self.service_url = config.config.get("service_url")
        self.api_key = config.config.get("api_key")
        self.timeout = config.config.get("timeout", 30)

    async def prompt_pre_fetch(self, payload, context):
        # Call external service
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{self.service_url}/analyze",
                    json={
                        "text": str(payload.args),
                        "policy": "strict"
                    },
                    headers={
                        "Authorization": f"Bearer {self.api_key}"
                    },
                    timeout=self.timeout
                )

                result = response.json()

                if result.get("blocked", False):
                    return PromptPrehookResult(
                        continue_processing=False,
                        violation=PluginViolation(
                            plugin_name=self.name,
                            description=result.get("reason", "Content blocked"),
                            violation_code="LLMGUARD_BLOCKED",
                            details=result
                        )
                    )

            except Exception as e:
                # Handle errors based on plugin settings
                if self.config.mode == PluginMode.ENFORCE:
                    return PromptPrehookResult(
                        continue_processing=False,
                        violation=PluginViolation(
                            plugin_name=self.name,
                            description=f"Service error: {str(e)}",
                            violation_code="SERVICE_ERROR",
                            details={"error": str(e)}
                        )
                    )

        return PromptPrehookResult()
```

## Plugin Development Guide

### 1. Create Plugin Directory

```bash
mkdir -p plugins/my_plugin
touch plugins/my_plugin/__init__.py
touch plugins/my_plugin/plugin.py
touch plugins/my_plugin/plugin-manifest.yaml
```

### 2. Write Plugin Manifest

```yaml
# plugins/my_plugin/plugin-manifest.yaml
description: "My custom plugin for X"
author: "Your Name"
version: "1.0.0"
tags: ["custom", "filter"]
available_hooks:
  - "prompt_pre_fetch"
  - "prompt_post_fetch"
default_config:
  setting_one: "default_value"
  setting_two: 123
```

### 3. Implement Plugin Class

```python
# plugins/my_plugin/plugin.py
from mcpgateway.plugins.framework import Plugin

class MyPlugin(Plugin):
    # Implementation here
    pass
```

### 4. Register in Configuration

```yaml
# plugins/config.yaml
plugins:
  - name: "MyCustomPlugin"
    kind: "plugins.my_plugin.plugin.MyPlugin"
    hooks: ["prompt_pre_fetch"]
    # ... other configuration
```

### 5. Test Your Plugin

```python
# tests/test_my_plugin.py
import pytest
from plugins.my_plugin.plugin import MyPlugin
from mcpgateway.plugins.framework import PluginConfig

@pytest.mark.asyncio
async def test_my_plugin():
    config = PluginConfig(
        name="test",
        kind="plugins.my_plugin.plugin.MyPlugin",
        hooks=["prompt_pre_fetch"],
        config={"setting_one": "test_value"}
    )

    plugin = MyPlugin(config)

    # Test your plugin logic
    result = await plugin.prompt_pre_fetch(payload, context)
    assert result.continue_processing
```

## Best Practices

### 1. Error Handling

Always handle errors gracefully:

```python
async def prompt_pre_fetch(self, payload, context):
    try:
        # Plugin logic
        pass
    except Exception as e:
        logger.error(f"Plugin {self.name} error: {e}")

        # In permissive mode, log and continue
        if self.mode == PluginMode.PERMISSIVE:
            return PromptPrehookResult()

        # In enforce mode, block the request
        return PromptPrehookResult(
            continue_processing=False,
            violation=PluginViolation(
                plugin_name=self.name,
                description="Plugin error occurred",
                violation_code="PLUGIN_ERROR",
                details={"error": str(e)}
            )
        )
```

### 2. Performance Considerations

- Keep plugin operations lightweight
- Use caching for expensive operations
- Respect the configured timeout
- Consider async operations for I/O

```python
class CachedPlugin(Plugin):
    def __init__(self, config):
        super().__init__(config)
        self._cache = {}
        self._cache_ttl = config.config.get("cache_ttl", 300)

    async def expensive_operation(self, key):
        # Check cache first
        if key in self._cache:
            cached_value, timestamp = self._cache[key]
            if time.time() - timestamp < self._cache_ttl:
                return cached_value

        # Perform expensive operation
        result = await self._do_expensive_work(key)

        # Cache result
        self._cache[key] = (result, time.time())
        return result
```

### 3. Conditional Execution

Use conditions to limit plugin scope:

```yaml
conditions:
  - prompts: ["sensitive_prompt"]
    server_ids: ["prod-server-1", "prod-server-2"]
    tenant_ids: ["enterprise-tenant"]
    user_patterns: ["admin-*", "support-*"]
```

### 4. Logging and Monitoring

Use appropriate log levels:

```python
logger.debug(f"Plugin {self.name} processing prompt: {payload.name}")
logger.info(f"Plugin {self.name} blocked request: {violation_code}")
logger.warning(f"Plugin {self.name} timeout approaching")
logger.error(f"Plugin {self.name} failed: {error}")
```

## API Reference

### Plugin Management Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/plugins` | GET | List all loaded plugins |
| `/plugins/stats` | GET | Get plugin execution statistics |
| `/plugins/reload/{name}` | POST | Reload a specific plugin |
| `/plugins/stats/reset` | POST | Reset plugin statistics |

### Example API Usage

```bash
# List plugins
curl http://localhost:8000/plugins

# Response
[
  {
    "name": "ContentFilter",
    "priority": 100,
    "mode": "enforce",
    "hooks": ["prompt_pre_fetch", "prompt_post_fetch"],
    "tags": ["security", "filter"],
    "conditions": {
      "prompts": ["customer_chat"]
    }
  }
]
```

## Troubleshooting

### Plugin Not Loading

1. Check server logs for initialization errors
2. Verify plugin class path in configuration
3. Ensure all dependencies are installed
4. Check Python import path includes plugin directory

### Plugin Not Executing

1. Verify plugin is enabled (`mode` != "disabled")
2. Check conditions match your request
3. Review priority ordering
4. Enable debug logging to see execution flow

### Performance Issues

1. Monitor plugin execution time in logs
2. Check for blocking I/O operations
3. Review timeout settings
4. Consider caching expensive operations

## Production Deployment Examples

### Enterprise AI Safety Pipeline

```yaml
# Production-grade AI safety configuration
plugins:
  # Step 1: PII Detection and Masking (Highest Priority)
  - name: "PIIFilter"
    kind: "plugins.pii_filter.pii_filter.PIIFilterPlugin"
    hooks: ["prompt_pre_fetch", "prompt_post_fetch", "tool_pre_invoke", "tool_post_invoke"]
    mode: "enforce"
    priority: 10
    config:
      detect_ssn: true
      detect_credit_card: true
      detect_email: true
      mask_strategy: "partial"
      block_on_detection: false

  # Step 2: External AI Safety Service (LlamaGuard)
  - name: "LlamaGuardSafety"
    kind: "external"
    hooks: ["prompt_pre_fetch", "tool_pre_invoke"]
    mode: "enforce"
    priority: 20
    mcp:
      proto: STREAMABLEHTTP
      url: "https://ai-safety.internal.corp/llamaguard/v1"
    conditions:
      - server_ids: ["production-chat", "customer-support"]

  # Step 3: OpenAI Moderation for Final Check
  - name: "OpenAIMod"
    kind: "external"
    hooks: ["prompt_post_fetch", "tool_post_invoke"]
    mode: "permissive"  # Log violations but don't block
    priority: 30
    mcp:
      proto: STREAMABLEHTTP
      url: "https://api.openai.com/v1/moderations"

  # Step 4: Audit Logging (Lowest Priority)
  - name: "AuditLogger"
    kind: "plugins.audit.audit_logger.AuditLoggerPlugin"
    hooks: ["prompt_pre_fetch", "tool_pre_invoke", "tool_post_invoke"]
    mode: "permissive"
    priority: 100
    config:
      log_level: "INFO"
      include_payloads: false  # For privacy
      audit_endpoints: ["https://audit.internal.corp/api/v1/logs"]
```

### Multi-Tenant Security Configuration

```yaml
plugins:
  # Enterprise tenant gets strict filtering
  - name: "EnterpriseSecurityFilter"
    kind: "plugins.security.enterprise_filter.EnterpriseFilterPlugin"
    hooks: ["prompt_pre_fetch", "tool_pre_invoke"]
    mode: "enforce"
    priority: 50
    conditions:
      - tenant_ids: ["enterprise-corp", "banking-client"]
        tools: ["database-query", "file-access", "system-command"]
    config:
      sql_injection_protection: true
      command_injection_protection: true
      file_system_restrictions: true

  # Free tier gets basic content filtering
  - name: "BasicContentFilter"
    kind: "plugins.content.basic_filter.BasicFilterPlugin"
    hooks: ["prompt_pre_fetch", "prompt_post_fetch"]
    mode: "permissive"
    priority: 75
    conditions:
      - tenant_ids: ["free-tier"]
    config:
      profanity_filter: true
      spam_detection: true
      rate_limit_warnings: true
```

### Development vs Production Configurations

```yaml
# Development Environment
plugins:
  - name: "DevPIIFilter"
    kind: "plugins.pii_filter.pii_filter.PIIFilterPlugin"
    hooks: ["prompt_pre_fetch", "tool_pre_invoke"]
    mode: "permissive"  # Don't block in dev
    priority: 50
    config:
      detect_ssn: true
      log_detections: true
      mask_strategy: "partial"
      whitelist_patterns:
        - "test@example.com"
        - "555-555-5555"
        - "123-45-6789"  # Test SSN

# Production Environment
plugins:
  - name: "ProdPIIFilter"
    kind: "plugins.pii_filter.pii_filter.PIIFilterPlugin"
    hooks: ["prompt_pre_fetch", "prompt_post_fetch", "tool_pre_invoke", "tool_post_invoke"]
    mode: "enforce"  # Block in production
    priority: 10
    config:
      detect_ssn: true
      detect_credit_card: true
      detect_phone: true
      detect_email: true
      detect_api_keys: true
      block_on_detection: true
      audit_detections: true
      compliance_mode: "strict"
```

## Performance and Scalability

### Benchmark Results

- **Self-Contained Plugins:** <1ms latency overhead per hook
- **External Service Plugins:** 10-100ms depending on service (cached responses: <5ms)
- **Memory Usage:** ~5MB base overhead + ~1MB per active plugin
- **Throughput:** Tested to 1,000+ req/s with 5 active plugins

### Performance Optimization Tips

```yaml
# Optimize plugin configuration for high-throughput environments
plugin_settings:
  plugin_timeout: 5000  # 5 second timeout for external services
  parallel_execution_within_band: true  # Enable when available
  fail_on_plugin_error: false  # Continue processing on plugin failures

plugins:
  - name: "CachedAIService"
    kind: "external"
    priority: 50
    config:
      cache_ttl_seconds: 300  # Cache responses for 5 minutes
      cache_max_entries: 10000  # LRU cache with 10K entries
      timeout_ms: 2000  # Fast timeout for high-throughput
      retry_attempts: 1  # Single retry only
```

## Monitoring and Observability

### Plugin Metrics

The framework exposes comprehensive metrics for monitoring:

```bash
# Plugin execution metrics
mcpgateway_plugin_executions_total{plugin="PIIFilter",hook="prompt_pre_fetch",status="success"}
mcpgateway_plugin_duration_seconds{plugin="PIIFilter",hook="prompt_pre_fetch"}
mcpgateway_plugin_violations_total{plugin="PIIFilter",violation_code="PII_DETECTED"}
mcpgateway_plugin_errors_total{plugin="LlamaGuard",error_type="timeout"}

# Context and memory metrics
mcpgateway_plugin_contexts_active
mcpgateway_plugin_contexts_cleaned_total
mcpgateway_plugin_memory_usage_bytes
```

### Health Check Integration

```yaml
plugins:
  - name: "ExternalAIService"
    kind: "external"
    mcp:
      proto: STREAMABLEHTTP
      url: "https://ai-service.corp/api/v1"
      health_check_endpoint: "/health"
      health_check_interval: 30
    config:
      circuit_breaker_enabled: true
      circuit_breaker_failure_threshold: 5
      circuit_breaker_timeout: 60
```

## Security Considerations

### Plugin Isolation and Security

- **Input Validation:** All plugin configurations validated against JSON schemas
- **Timeout Protection:** Configurable timeouts prevent plugin hangs
- **Resource Limits:** Memory and payload size limits prevent resource exhaustion
- **Error Isolation:** Plugin failures don't affect gateway stability
- **Audit Logging:** Complete audit trail of plugin executions and violations

### External Service Security

```yaml
# Secure external service configuration
plugins:
  - name: "SecureExternalService"
    kind: "external"
    mcp:
      proto: STREAMABLEHTTP
      url: "https://secure-ai-service.corp/api/v1"
      tls_verify: true
      tls_client_cert: "/etc/ssl/certs/client.crt"
      tls_client_key: "/etc/ssl/private/client.key"
      auth:
        type: "bearer"
        token: "${AI_SERVICE_TOKEN}"  # Environment variable
    config:
      allowed_response_codes: [200, 201]
      max_response_size_mb: 10
      connection_pool_size: 20
```

## Future Roadmap

### Near-term Enhancements (v0.7.0)

- **Server Attestation Hooks:** `server_pre_register` with TPM/TEE support
- **Authentication Hooks:** `auth_pre_check`/`auth_post_check` for custom auth
- **Admin UI:** Visual plugin management and monitoring dashboard
- **Hot Configuration Reload:** Update plugin configs without restart
- **Advanced Caching:** Redis-backed caching for external service calls

### Long-term Vision (v0.8.0+)

- **Plugin Marketplace:** Community plugin sharing and discovery
- **Advanced Analytics:** Plugin performance analytics and optimization recommendations
- **A/B Testing Framework:** Split traffic between plugin configurations
- **Policy as Code:** Integration with Open Policy Agent (OPA) for complex rule evaluation
- **Machine Learning Pipeline:** Built-in support for custom ML model deployment

## Contributing

To contribute a plugin:

1. Follow the plugin structure guidelines
2. Include comprehensive tests
3. Document configuration options
4. Submit a pull request with examples

For framework improvements, please open an issue to discuss proposed changes.
