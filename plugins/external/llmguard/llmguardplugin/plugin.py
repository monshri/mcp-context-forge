"""A plugin that leverages the capabilities of llmguard library to apply guardrails on input and output prompts.

Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Shriti Priya

This module loads configurations for plugins.
"""

# First-Party
from mcpgateway.plugins.framework import (
    Plugin,
    PluginConfig,
    PluginContext,
    PromptPosthookPayload,
    PromptPosthookResult,
    PromptPrehookPayload,
    PromptPrehookResult,
    ToolPostInvokePayload,
    ToolPostInvokeResult,
    ToolPreInvokePayload,
    ToolPreInvokeResult,
)
from llmguardplugin.schema import LLMGuardConfig
from llmguardplugin.llmguard import LLMGuardBase
from mcpgateway.plugins.framework.models import PluginConfig, PluginViolation
from mcpgateway.services.logging_service import LoggingService


# Initialize logging service first
logging_service = LoggingService()
logger = logging_service.get_logger(__name__)


class LLMGuardPlugin(Plugin):
    """A plugin that leverages the capabilities of llmguard library to apply guardrails on input and output prompts."""

    def __init__(self, config: PluginConfig):
        """Entry init block for plugin.

        Args:
          logger: logger that the skill can make use of
          config: the skill configuration
        """
        super().__init__(config)
        self.lgconfig = LLMGuardConfig.model_validate(self._config.config)
        self.llmguard_instance = LLMGuardBase(config=self._config.config)
                
    async def prompt_pre_fetch(self, payload: PromptPrehookPayload, context: PluginContext) -> PromptPrehookResult:
        """The plugin hook run before a prompt is retrieved and rendered.

        Args:
            payload: The prompt payload to be analyzed.
            context: contextual information about the hook call.

        Returns:
            The result of the plugin's analysis, including whether the prompt can proceed.
        """
        logger.info(f"Processing config {payload}")
        if payload.args:
            for key in payload.args:
                if self.lgconfig.input.filters:
                    logger.info(f"payload {payload}")
                    logger.info(f"payload {context}")
                    context.state["original_prompt"] = payload.args[key] 
                    logger.info(f"shriti {context.state}")
                    result = self.llmguard_instance._apply_input_filters(payload.args[key])
                    logger.info(f"payload {result}")
                    decision = self.llmguard_instance._apply_policy_input(result)
                    #NOTE: Check how to return denial
                    if not decision[0]:
                        payload.args[key] = decision[1]
                        violation = PluginViolation(
                        reason="Prompt not allowed",
                        description="{threat} detected in the prompt".format(threat=list(decision[2].keys())[0]),
                        code="deny",
                        details=decision[2],)
                        return PromptPrehookResult(modified_payload=payload, violation=violation, continue_processing=False)
        
        return PromptPrehookResult(continue_processing=True)

    async def prompt_post_fetch(self, payload: PromptPosthookPayload, context: PluginContext) -> PromptPosthookResult:
        """Plugin hook run after a prompt is rendered.

        Args:
            payload: The prompt payload to be analyzed.
            context: Contextual information about the hook call.

        Returns:
            The result of the plugin's analysis, including whether the prompt can proceed.
        """
        logger.info(f"shriti post {context.state}")
        if not payload.result.messages:
            return PromptPosthookResult()

        # Process each message
        for message in payload.result.messages:
            if message.content and hasattr(message.content, 'text'):
                if self.lgconfig.output:
                    text = message.content.text
                    logger.info(f"Applying output guardrails on {text}")
                    logger.info(f"Applying output guardrails using context {context.state["original_prompt"]}")
                    result = self.llmguard_instance._apply_output_filters(context.state["original_prompt"],text)
                    decision = self.llmguard_instance._apply_policy_output(result)
                    logger.info(f"shriti decision {decision}")
                    if not decision[0]:
                            violation = PluginViolation(
                            reason="Output not allowed",
                            description="{threat} detected in the prompt".format(threat=list(decision[2].keys())[0]),
                            code="deny",
                            details=decision[2],)
                            return PromptPosthookResult(modified_payload=payload, violation=violation, continue_processing=False)
        return PromptPosthookResult(continue_processing=True)

    async def tool_pre_invoke(self, payload: ToolPreInvokePayload, context: PluginContext) -> ToolPreInvokeResult:
        """Plugin hook run before a tool is invoked.

        Args:
            payload: The tool payload to be analyzed.
            context: Contextual information about the hook call.

        Returns:
            The result of the plugin's analysis, including whether the tool can proceed.
        """
        return ToolPreInvokeResult(continue_processing=True)

    async def tool_post_invoke(self, payload: ToolPostInvokePayload, context: PluginContext) -> ToolPostInvokeResult:
        """Plugin hook run after a tool is invoked.

        Args:
            payload: The tool result payload to be analyzed.
            context: Contextual information about the hook call.

        Returns:
            The result of the plugin's analysis, including whether the tool result should proceed.
        """
        return ToolPostInvokeResult(continue_processing=True)
