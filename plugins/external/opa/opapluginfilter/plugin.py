# -*- coding: utf-8 -*-
"""An OPA plugin that enforces rego policies on requests and allows/denies requests as per policies.

Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Shriti Priya

This module loads configurations for plugins and applies hooks on pre/post requests for tools, prompts and resources.
"""

# Standard
from typing import Any, Union

# Third-Party
from opapluginfilter.schema import BaseOPAInputKeys, OPAConfig, OPAInput
import requests
from enum import Enum

# First-Party
from mcpgateway.plugins.framework import (
    Plugin,
    PluginConfig,
    PluginContext,
    PluginViolation,
    PromptPosthookPayload,
    PromptPosthookResult,
    PromptPrehookPayload,
    PromptPrehookResult,
    ToolPostInvokePayload,
    ToolPostInvokeResult,
    ToolPreInvokePayload,
    ToolPreInvokeResult,
)
from mcpgateway.services.logging_service import LoggingService

# Initialize logging service first
logging_service = LoggingService()
logger = logging_service.get_logger(__name__)


class OPACodes(str,Enum):
    ALLOW_CODE = "ALLOW"
    DENIAL_CODE = "DENY"
    AUDIT_CODE = "AUDIT"
    REQUIRES_HUMAN_APPROVAL_CODE = "REQUIRES_APPROVAL"



class OPAPluginFilter(Plugin):
    """An OPA plugin that enforces rego policies on requests and allows/denies requests as per policies."""

    def __init__(self, config: PluginConfig):
        """Entry init block for plugin.

        Args:
          logger: logger that the skill can make use of
          config: the skill configuration
        """
        super().__init__(config)
        self.opa_config = OPAConfig.model_validate(self._config.config)
        self.opa_context_key = "opa_policy_context"

    def _get_nested_value(self, data, key_string, default=None):
        """
        Retrieves a value from a nested dictionary using a dot-notation string.

        Args:
            data (dict): The dictionary to search within.
            key_string (str): The dot-notation string representing the path to the value.
            default (any, optional): The value to return if the key path is not found.
                                    Defaults to None.

        Returns:
            any: The value at the specified key path, or the default value if not found.
        """
        keys = key_string.split(".")
        current_data = data
        for key in keys:
            if isinstance(current_data, dict) and key in current_data:
                current_data = current_data[key]
            else:
                return default  # Key not found at this level
        return current_data

    def _evaluate_opa_policy(self, url: str, input: OPAInput, policy_input_data_map: dict) -> tuple[bool, Any]:
        """Function to evaluate OPA policy. Makes a request to opa server with url and input.

        Args:
            url: The url to call opa server
            input: Contains the payload of input to be sent to opa server for policy evaluation.

        Returns:
            True, json_response if the opa policy is allowed else false. The json response is the actual response returned by OPA server.
            If OPA server encountered any error, the return would be True (to gracefully exit) and None would be the json_response, marking
            an issue with the OPA server running.

        """

        def _key(k: str, m: str) -> str:
            return f"{k}.{m}" if k.split(".")[0] == "context" else k

        payload = {"input": {m: self._get_nested_value(input.model_dump()["input"], _key(k, m)) for k, m in policy_input_data_map.items()}} if policy_input_data_map else input.model_dump()
        logger.info(f"OPA url {url}, OPA payload {payload}")
        rsp = requests.post(url, json=payload)
        logger.info(f"OPA connection response '{rsp}'")
        if rsp.status_code == 200:
            json_response = rsp.json()
            decision = json_response.get("result", None)
            logger.info(f"OPA server response '{json_response}'")
            if isinstance(decision, bool):
                logger.debug(f"OPA decision {decision}")
                return decision, json_response
            elif isinstance(decision, dict) and "allow" in decision:
                allow = decision["allow"]
                logger.debug(f"OPA decision {allow}")
                return allow, json_response
            else:
                logger.debug(f"OPA sent a none response {json_response}")
        else:
            logger.debug(f"OPA error: {rsp}")
        return True, None

    def _preprocess_opa(self,policy_apply_config,payload,context,hook_type="tool_pre_invoke") -> dict:
        result = {
            "opa_server_url" : None,
            "policy_context" : None,
            "policy_input_data_map" : None
        }
        input_context = []
        policy_context = {}
        policy = None
        policy_endpoint = None
        policy_input_data_map = {}
        hook_name = None
        
        if policy_apply_config: 
            if "tool" in hook_type and policy_apply_config.tools:
                hook_info = policy_apply_config.tools
            elif "prompt" in hook_type and  policy_apply_config.prompts:
                hook_info = policy_apply_config.prompts
            elif "resource" in hook_type and  policy_apply_config.resources:
                hook_info = policy_apply_config.resources
            else:
                logger.error("Error")
                
            for hook in hook_info:
                hook_name = hook.name
                if payload.name == "name":
                    input_context = [ctx.rsplit(".", 1)[-1] for ctx in hook.context]
                if self.opa_context_key in context.global_context.state:
                    policy_context = {k: context.global_context.state[self.opa_context_key][k] for k in input_context}
                if hook.extensions:
                    policy = hook.extensions.get("policy", None)
                    tool_policy_endpoints = hook.extensions.get("policy_endpoints", None)
                    if tool_policy_endpoints:
                        for endpoint in tool_policy_endpoints:
                            policy_endpoint= endpoint if endpoint.contains(hook_type) else None
                    policy_input_data_map = hook.extensions.get("policy_input_data_map", {})
        
        if not policy_endpoint:
            logger.debug(f"Unconfigured endpoint for policy {hook_type} {hook_name} invocation:")
            return None
        
        result["policy_context"] = policy_context
        result["opa_server_url"] = "{opa_url}{policy}/{policy_endpoint}".format(opa_url=self.opa_config.opa_base_url, policy=policy, policy_endpoint=policy_endpoint)
        result["policy_input_data_map"] = policy_input_data_map        
        return result
        

    async def prompt_pre_fetch(self, payload: PromptPrehookPayload, context: PluginContext) -> PromptPrehookResult:
        """The plugin hook run before a prompt is retrieved and rendered.

        Args:
            payload: The prompt payload to be analyzed.
            context: contextual information about the hook call.

        Returns:
            The result of the plugin's analysis, including whether the prompt can proceed.
        """
        policy_apply_config = self._config.applied_to
        if payload.args:
            for key in payload.args:
                text = payload.args[key]
                opa_pre_prompt_input = self._preprocess_opa(policy_apply_config,payload,context,"prompt_pre_fetch")
                if opa_pre_prompt_input:
                    decision, decision_context = self._evaluate_opa_policy(url=opa_pre_tool_input["opa_server_url"], input=OPAInput(input=opa_pre_tool_input["opa_input"]), policy_input_data_map=opa_pre_tool_input["policy_input_data_map"])
                    if not decision:
                            violation = PluginViolation(
                                reason="tool invocation not allowed",
                                description="OPA policy denied for tool preinvocation",
                                code=OPACodes.DENIAL_CODE,
                                details=decision_context,
                            )
                            return ToolPreInvokeResult(modified_payload=payload, violation=violation, continue_processing=False)        
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
        """OPA Plugin hook run before a tool is invoked. This hook takes in payload and context and further evaluates rego
        policies on the input by sending the request to opa server.

        Args:
            payload: The tool payload to be analyzed.
            context: Contextual information about the hook call.

        Returns:
            The result of the plugin's analysis, including whether the tool can proceed.
        """

        logger.info(f"Processing tool pre-invoke for tool '{payload.name}' with {len(payload.args) if payload.args else 0} arguments")
        logger.info(f"Processing tool context {context}")

        if not payload.args:
            return ToolPreInvokeResult()
        
        # Get the tool for which policy needs to be applied
        policy_apply_config = self._config.applied_to
        if policy_apply_config and policy_apply_config.tools:
            opa_pre_tool_input = self._preprocess_opa(policy_apply_config,payload,context,"tool")
            if opa_pre_tool_input:
                decision, decision_context = self._evaluate_opa_policy(url=opa_pre_tool_input["opa_server_url"], input=OPAInput(input=opa_pre_tool_input["opa_input"]), policy_input_data_map=opa_pre_tool_input["policy_input_data_map"])
                if not decision:
                        violation = PluginViolation(
                            reason="tool invocation not allowed",
                            description="OPA policy denied for tool preinvocation",
                            code=OPACodes.DENIAL_CODE,
                            details=decision_context,
                        )
                        return ToolPreInvokeResult(modified_payload=payload, violation=violation, continue_processing=False)
        
        return ToolPreInvokeResult(continue_processing=True)


    async def tool_post_invoke(self, payload: ToolPostInvokePayload, context: PluginContext) -> ToolPostInvokeResult:
        """Plugin hook run after a tool is invoked. The response of the tool passes through this hook and opa policy is evaluated on it
         for it to be allowed or denied.

        Args:
            payload: The tool result payload to be analyzed.
            context: Contextual information about the hook call.

        Returns:
            The result of the plugin's analysis, including whether the tool result should proceed.
        """
        logger.info(f"here is the payload {payload.result}")
        
        if not payload.result:
            return ToolPostInvokeResult()
        
        result_text = []
        if hasattr(payload.result,"content"):
            if isinstance(payload.result.content, list):
                for item in payload.result.content:
                    if hasattr(item, "text") and isinstance(item.text, str):
                        result_text.append(item.text)
                    elif hasattr(item,"text") and isinstance(item.text,dict):
                        for value in item.values():
                            if isinstance(value, str):
                                result_text.append(value)
                    else:
                        logger.debug("The input doesn't have text attribute")

    
        policy_apply_config = self._config.applied_to
        if policy_apply_config and policy_apply_config.tools:
            opa_post_tool_input = self._preprocess_opa(policy_apply_config,payload,context,"tool")
            if opa_post_tool_input:
                opa_input = BaseOPAInputKeys(kind="post_tool", user="none", payload=result_text, context=opa_post_tool_input["policy_context"], request_ip="none", headers={}, response={}, mode="output")
                decision, decision_context = self._evaluate_opa_policy(url=opa_post_tool_input["opa_server_url"], input=OPAInput(input=opa_input), policy_input_data_map=opa_post_tool_input["policy_input_data_map"])
                if not decision:
                        violation = PluginViolation(
                            reason="tool invocation not allowed",
                            description="OPA policy denied for tool postinvocation",
                            code=OPACodes.DENIAL_CODE,
                            details=decision_context,
                        )
                        return ToolPostInvokeResult(modified_payload=payload, violation=violation, continue_processing=False)
        return ToolPostInvokeResult(continue_processing=True)
