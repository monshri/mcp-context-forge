# -*- coding: utf-8 -*-
"""A plugin that leverages the capabilities of llmguard library to apply guardrails on input and output prompts.

Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Shriti Priya

This module loads configurations for plugins.
"""

# First-Party
from llmguardplugin.schema import LLMGuardConfig
from llmguardplugin.llmguard import LLMGuardBase
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
from mcpgateway.plugins.framework.models import PluginConfig, PluginViolation
from mcpgateway.plugins.framework import PluginError, PluginErrorModel
from mcpgateway.services.logging_service import LoggingService
from llmguardplugin.cache import CacheTTLDict


# Initialize logging service first
logging_service = LoggingService()
logger = logging_service.get_logger(__name__)


class LLMGuardPlugin(Plugin):
    """A plugin that leverages the capabilities of llmguard library to apply guardrails on input and output prompts.
    
    Attributes:
        lgconfig: Configuration for guardrails.
        cache: Cache object of class CacheTTLDict for plugins.
        guardrails_context_key: Key to set in context for any guardrails related processing and information storage.
        """

    def __init__(self, config: PluginConfig) -> None:
        """Entry init block for plugin. Validates the configuration of plugin and initializes an instance of LLMGuardBase with the config

        Args:
          config: the skill configuration
        """
        super().__init__(config)
        self.lgconfig = LLMGuardConfig.model_validate(self._config.config)
        self.cache = CacheTTLDict(ttl=self.lgconfig.cache_ttl)
        self.guardrails_context_key = "guardrails"
        if self.__verify_lgconfig():
            self.llmguard_instance = LLMGuardBase(config=self._config.config)
        else:
            raise PluginError(error=PluginErrorModel(message="Invalid configuration for plugin initilialization", plugin_name=self.name))

    def __verify_lgconfig(self):
        """Checks if the configuration provided for plugin is valid or not. It should either have input or output key atleast"""
        return self.lgconfig.input or self.lgconfig.output

    async def prompt_pre_fetch(self, payload: PromptPrehookPayload, context: PluginContext) -> PromptPrehookResult:
        """The plugin hook to apply input guardrails on using llmguard.

        Args:
            payload: The prompt payload to be analyzed.
            context: contextual information about the hook call.

        Returns:
            The result of the plugin's analysis, including whether the prompt can proceed.
        """
        logger.info(f"Processing payload {payload}")
        if payload.args:
            for key in payload.args: 
                # Set context to pass original prompt within and across plugins
                if self.lgconfig.input.filters or self.lgconfig.input.sanitizers:
                    context.state[self.guardrails_context_key] = {}
                    context.global_context.state[self.guardrails_context_key] = {}
                    context.state[self.guardrails_context_key]["original_prompt"] = payload.args[key]
                    context.global_context.state[self.guardrails_context_key]["original_prompt"] = payload.args[key]
                
                # Apply input filters if set in config
                if self.lgconfig.input.filters:
                    logger.info(f"Applying input guardrail filters on {payload.args[key]}")
                    result = self.llmguard_instance._apply_input_filters(payload.args[key])
                    logger.info(f"Result of input guardrail filters: {result}")
                    decision = self.llmguard_instance._apply_policy_input(result)
                    logger.info(f"Result of policy decision: {decision}")
                    if not decision[0]:
                        violation = PluginViolation(
                        reason=decision[1],
                        description="{threat} detected in the prompt".format(threat=list(decision[2].keys())[0]),
                        code="deny",
                        details=decision[2],)
                        return PromptPrehookResult(violation=violation, continue_processing=False)
                
                # Apply input sanitizers if set in config
                if self.lgconfig.input.sanitizers:
                    # initialize a context key "guardrails"
                    logger.info(f"Applying input guardrail sanitizers on {payload.args[key]}")
                    result = self.llmguard_instance._apply_input_sanitizers(payload.args[key])
                    logger.info(f"Result of input guardrail sanitizers on {result}")
                    if not result:
                        violation = PluginViolation(
                        reason="Attempt to breach vault",
                        description="{threat} detected in the prompt".format(threat="vault_leak"),
                        code="deny",
                        details={},)
                        logger.info(f"violation {violation}")
                        return PromptPrehookResult(violation=violation, continue_processing=False)
                    # Set context for the vault if used
                    _, vault_id, vault_tuples = self.llmguard_instance._retreive_vault()
                    if vault_id and vault_tuples:
                        success, _ = self.cache.update_cache(vault_id,vault_tuples)
                        # If cache update was successful, then store it in the context to pass further
                        if success:
                            context.global_context.state[self.guardrails_context_key]["vault_cache_id"] = vault_id
                            context.state[self.guardrails_context_key]["vault_cache_id"] = vault_id
                    payload.args[key] = result[0]
        
        # Set context for the original prompt to be passed further
        return PromptPrehookResult(continue_processing=True,modified_payload=payload)

    async def prompt_post_fetch(self, payload: PromptPosthookPayload, context: PluginContext) -> PromptPosthookResult:
        """Plugin hook to apply output guardrails on output.

        Args:
            payload: The prompt payload to be analyzed.
            context: Contextual information about the hook call.

        Returns:
            The result of the plugin's analysis, including whether the prompt can proceed.
        """
        logger.info(f"Processing result {payload.result}")
        if not payload.result.messages:
            return PromptPosthookResult()

        vault_id = None
        original_prompt = ""
        # Process each message
        for message in payload.result.messages:
            if message.content and hasattr(message.content, 'text'):
                if self.lgconfig.output.filters or self.lgconfig.output.sanitizers:
                    if self.guardrails_context_key in context.state:
                        original_prompt = context.state[self.guardrails_context_key]["original_prompt"] if "original_prompt" in context.state[self.guardrails_context_key] else ""
                        vault_id = context.state[self.guardrails_context_key]["vault_cache_id"] if "vault_cache_id" in context.state[self.guardrails_context_key] else None
                    if self.guardrails_context_key in context.global_context.state:
                        original_prompt = context.global_context.state[self.guardrails_context_key]["original_prompt"] if "original_prompt" in context.global_context.state[self.guardrails_context_key] else ""
                        vault_id = context.global_context.state[self.guardrails_context_key]["vault_cache_id"] if "vault_cache_id" in context.global_context.state[self.guardrails_context_key] else None
                if self.lgconfig.output.sanitizers:
                    text = message.content.text
                    logger.info(f"Applying output sanitizers on {text}")
                    if vault_id:
                        vault_obj = self.cache.retrieve_cache(vault_id)
                        scanner_config = {"Deanonymize" : vault_obj}
                        self.llmguard_instance._update_output_sanitizers(scanner_config)
                    result = self.llmguard_instance._apply_output_sanitizers(original_prompt,text)
                    logger.info(f"Result of output sanitizers: {result}")
                    message.content.text = result[0]

                if self.lgconfig.output.filters:
                    text = message.content.text
                    logger.info(f"Applying output guardrails on {text}")
                    result = self.llmguard_instance._apply_output_filters(original_prompt,text)
                    decision = self.llmguard_instance._apply_policy_output(result)
                    logger.info(f"Policy decision on output guardrails: {decision}")
                    if not decision[0]:
                            violation = PluginViolation(
                            reason=decision[1],
                            description="{threat} detected in the prompt".format(threat=list(decision[2].keys())[0]),
                            code="deny",
                            details=decision[2],)
                            return PromptPosthookResult(violation=violation, continue_processing=False)
        return PromptPosthookResult(continue_processing=True,modified_payload=payload)

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
