"""A plugin that leverages the capabilities of llmguard library to apply guardrails on input and output prompts.

Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Shriti Priya

This module loads configurations for plugins.
"""

# Third-Party
from llm_guard import input_scanners, output_scanners
from llm_guard import scan_output, scan_prompt

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
from mcpgateway.plugins.framework.models import PluginConfig, PluginViolation
from mcpgateway.services.logging_service import LoggingService
from llmguardplugin.schema import LLMGuardConfig, ModeConfig
from llmguardplugin.policy import GuardrailPolicy, get_policy_filters


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
        self._lgconfig = LLMGuardConfig.model_validate(self._config.config)
        self._scanners = {"input": {"sanitizers": [], "filters" : []}}
        logger.info(f"Processing scanners {self._scanners}")
        logger.info(f"Processing config {self._lgconfig}")
        self.__init_scanners()

    
    def _load_policy_scanners(self,config):
        scanner_names = get_policy_filters(config['policy'] if "policy" in config else get_policy_filters(config["filters"]))
        return scanner_names

    def _initialize_input_scanners(self):
        if self._lgconfig.input.filters:
            policy_filter_names = self._load_policy_scanners(self._lgconfig.input.filters)
            for filter_name in policy_filter_names:
                self._scanners["input"]["filters"].append(
                    input_scanners.get_scanner_by_name(filter_name,self._lgconfig.input.filters[filter_name]))
        elif self._lgconfig.input.sanitizers:
            sanitizer_names = self._lgconfig.input.sanitizers.keys()
            for sanitizer_name in sanitizer_names:
                self._scanners["input"]["sanitizers"].append(
                    input_scanners.get_scanner_by_name(sanitizer_name,self._lgconfig.input.sanitizers[sanitizer_name]))
        else:
            logger.error("Error initializing filters")
    
    
    def _initialize_output_scanners(self):
        if self._lgconfig.output.filters:
            policy_filter_names = self._load_policy_scanners(self._lgconfig.output.filters)
            for filter_name in policy_filter_names:
                self._scanners["output"]["filters"].append(
                    output_scanners.get_scanner_by_name(filter_name,self._lgconfig.output.filters[filter_name]))
        elif self._lgconfig.output.sanitizers:
            sanitizer_names = self._lgconfig.output.sanitizers.keys()
            for sanitizer_name in sanitizer_names:
                self._scanners["input"]["sanitizers"].append(
                    input_scanners.get_scanner_by_name(sanitizer_name,self._lgconfig.output.sanitizers[sanitizer_name]))
        else:
            logger.error("Error initializing filters")

    def __init_scanners(self):
        if self._lgconfig.input:
            self._initialize_input_scanners()
        if self._lgconfig.output:
            self._initialize_output_scanners()
        #NOTE: Check if we load from default just as in Skillet


    def _apply_input_filters(self,input_prompt):
        result = {}
        for scanner in self._scanners["input"]["filters"]:
            sanitized_prompt, is_valid, risk_score = scanner.scan(input_prompt)
            scanner_name = type(scanner).__name__
            result[scanner_name] = {
                "sanitized_prompt": sanitized_prompt,
                "is_valid": is_valid,
                "risk_score": risk_score,
            }

        return result    
    

    def _apply_input_sanitizers(self,input_prompt):
        result = scan_prompt(self._scanners["input"]["sanitizers"], input_prompt)
        return result
    
    def _apply_output_filters(self,original_input,model_response):
        result = {}
        for scanner in self._scanners["output"]["filters"]:
            sanitized_prompt, is_valid, risk_score = scanner.scan(original_input, model_response)
            scanner_name = type(scanner).__name__
            result[scanner_name] = {
                "sanitized_prompt": sanitized_prompt,
                "is_valid": is_valid,
                "risk_score": risk_score,
            }
        return result
    
    def _apply_output_sanitizers(self, input_prompt, model_response):
        result = scan_output(self._scanners["output"]["sanitizers"], input_prompt, model_response)
        return result
    
    def _apply_policy(self,result_scan):
        policy_expression = self._lgconfig.input.filters['policy'] if 'policy' in self._lgconfig.input.filters else " and ".join(list(self._lgconfig.input.filters))
        policy_message = self._lgconfig.input.filters['policy_message'] if 'policy_message' in self._lgconfig.input.filters else "Request Forbidden"
        policy = GuardrailPolicy()
        if not policy.evaluate(policy_expression, result_scan):
            return False, policy_message, result_scan
        return True, policy_message, result_scan
    
    
    async def prompt_pre_fetch(self, payload: PromptPrehookPayload, context: PluginContext) -> PromptPrehookResult:
        """The plugin hook run before a prompt is retrieved and rendered.

        Args:
            payload: The prompt payload to be analyzed.
            context: contextual information about the hook call.

        Returns:
            The result of the plugin's analysis, including whether the prompt can proceed.
        """
        if payload.args:
            for key in payload.args:
                if self._lgconfig.input.filters:
                    logger.info(f"payload {payload}")
                    result = self._apply_input_filters(payload.args[key])
                    logger.info(f"payload {result}")
                    decision = self._apply_policy(result)
                    #NOTE: Check how to return denial
                    if not decision[0]:
                        payload.args[key] = decision[1]
                        violation = PluginViolation(
                        reason="Prompt not allowed",
                        description="{threat} detected in the prompt".format(threat=list(decision[2].keys())[0]),
                        code="deny",
                        details=decision[2],)
                        return PromptPrehookResult(modified_payload=payload, violation=violation, continue_processing=False)
                if self._lgconfig.input.sanitizers:
                    result = self._apply_input_sanitizers(payload.args[key])
                    payload.args[key] = result[0]
        return PromptPrehookResult(continue_processing=True)

    async def prompt_post_fetch(self, payload: PromptPosthookPayload, context: PluginContext) -> PromptPosthookResult:
        """Plugin hook run after a prompt is rendered.

        Args:
            payload: The prompt payload to be analyzed.
            context: Contextual information about the hook call.

        Returns:
            The result of the plugin's analysis, including whether the prompt can proceed.
        """
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
