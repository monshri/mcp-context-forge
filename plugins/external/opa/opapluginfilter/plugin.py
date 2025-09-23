# -*- coding: utf-8 -*-
"""An OPA plugin that enforces rego policies on requests and allows/denies requests as per policies.

Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Shriti Priya

This module loads configurations for plugins and applies hooks on pre/post requests for tools, prompts and resources.
"""

# Standard
from typing import Any

# Third-Party
from opapluginfilter.schema import BaseOPAInputKeys, OPAConfig, OPAInput
import requests

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

    def _create_human_context_message():
        return


    def _evaluate_opa_policy(self, url: str, input: OPAInput, policy_input_data_map: dict) -> tuple[Any, Any]:
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
                requires_approval = decision["requires_approval"] if "requires_approval" in decision else False
                if requires_approval and allow:
                    logger.debug(f"OPA decision requires_approval {requires_approval} and {allow}")
                    return "requires_approval",decision
                logger.debug(f"OPA decision {allow}")
                return allow, decision
            else:
                logger.debug(f"OPA sent a none response {json_response}")
        else:
            logger.debug(f"OPA error: {rsp}")
        return True, None

    async def prompt_pre_fetch(self, payload: PromptPrehookPayload, context: PluginContext) -> PromptPrehookResult:
        """The plugin hook run before a prompt is retrieved and rendered.

        Args:
            payload: The prompt payload to be analyzed.
            context: contextual information about the hook call.

        Returns:
            The result of the plugin's analysis, including whether the prompt can proceed.
        """
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

        tool_context = []
        policy_context = {}
        tool_policy = None
        tool_policy_endpoint = None
        tool_policy_input_data_map = {}
        # Get the tool for which policy needs to be applied
        policy_apply_config = self._config.applied_to
        if policy_apply_config and policy_apply_config.tools:
            for tool in policy_apply_config.tools:
                tool_name = tool.tool_name
                if payload.name == tool_name:
                    if tool.context:
                        tool_context = [ctx.rsplit(".", 1)[-1] for ctx in tool.context]
                    if self.opa_context_key in context.global_context.state:
                        policy_context = {k: context.global_context.state[self.opa_context_key][k] for k in tool_context}
                    if tool.extensions:
                        tool_policy = tool.extensions.get("policy", None)
                        tool_policy_endpoint = tool.extensions.get("policy_endpoint", None)
                        tool_policy_input_data_map = tool.extensions.get("policy_input_data_map", {})

                    opa_input = BaseOPAInputKeys(kind="tools/call", user="none", payload=payload.model_dump(), context=policy_context, request_ip="none", headers={}, response={})
                    opa_server_url = "{opa_url}{policy}/{policy_endpoint}".format(opa_url=self.opa_config.opa_base_url, policy=tool_policy, policy_endpoint=tool_policy_endpoint)
                    decision, decision_context = self._evaluate_opa_policy(url=opa_server_url, input=OPAInput(input=opa_input), policy_input_data_map=tool_policy_input_data_map)
                    if isinstance(decision,str):
                        if decision == "requires_approval":
                            logger.info(f"Update context {context}")
                            logger.info(f"Update context {decision}, {decision_context}")
                            context.global_context.state[decision] = True
                            context.global_context.state["audit_decision"] = decision_context["audit_decision"] if "audit_decision" in decision_context else {}
                            logger.info(f"Update context {context}")

                    if not decision:
                        violation = PluginViolation(
                            reason="tool invocation not allowed",
                            description="OPA policy denied for tool preinvocation",
                            code="deny",
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
        return ToolPostInvokeResult(continue_processing=True)
