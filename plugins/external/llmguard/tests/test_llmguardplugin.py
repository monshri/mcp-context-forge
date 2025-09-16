# -*- coding: utf-8 -*-
"""Tests for plugin."""

# Third-Party
import pytest

# First-Party
from llmguardplugin.plugin import LLMGuardPlugin
from mcpgateway.plugins.framework import (
    PluginConfig,
    PluginContext,
    PromptPrehookPayload,
    GlobalContext
)


@pytest.mark.asyncio
async def test_llmguardplugin():
    """Test plugin prompt prefetch hook."""
    filter_config = {
        "input" : {
            "filters" : {
                "PromptInjection": {
                    "threshold" : 0.6,
                    "use_onnx" : False
                },
                "policy" : "PromptInjection",
                "policy_message": "I'm sorry, I'm afraid I can't do that."
            }
        }
    }

    config = PluginConfig(
        name="test",
        kind="llmguardplugin.LLMGuardPlugin",
        hooks=["prompt_pre_fetch"],
        config=filter_config,
    )
    plugin = LLMGuardPlugin(config)

    # Test your plugin logic
    payload = PromptPrehookPayload(name="test_prompt", args={"arg0": "This is an argument"})
    context = PluginContext(global_context=GlobalContext(request_id="1", server_id="2"))
    result = await plugin.prompt_pre_fetch(payload, context)
    assert result.continue_processing
