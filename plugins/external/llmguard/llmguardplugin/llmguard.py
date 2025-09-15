"""A base class that leverages core functionality of LLMGuard and leverages it to apply guardrails on input and output.
It imports llmguard library, and uses it to apply two or more filters, combined by the logic of policy defined by the user.

Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Shriti Priya

"""

# Standard
from typing import Any, Optional, Union


# Third-Party
from llm_guard import input_scanners, output_scanners
from llm_guard import scan_output, scan_prompt

# First-Party
from llmguardplugin.schema import LLMGuardConfig, ModeConfig
from llmguardplugin.policy import GuardrailPolicy, get_policy_filters
from mcpgateway.services.logging_service import LoggingService

# Initialize logging service first
logging_service = LoggingService()
logger = logging_service.get_logger(__name__)

class LLMGuardBase():
    """Base class that leverages LLMGuard library to apply a combination of filters (returns true of false, allowing or denying an input (like PromptInjection)) and sanitizers (transforms the input, like Anonymizer and Deanonymizer) for both input and output prompt.

    Attributes:
        lgconfig: Configuration for guardrails.
        scanners: Sanitizers and filters defined for input and output.
    """
    def __init__(self, config: Optional[dict[str, Any]]) -> None:
        self.lgconfig = LLMGuardConfig.model_validate(config)
        self.scanners = {"input": {"sanitizers": [], "filters" : []}, "output": {"sanitizers": [], "filters" : []}}
        self.__init_scanners()
     
    def _load_policy_scanners(self,config: dict = None) -> Union[list,None]:
        """Loads all the scanner names defined in a policy.

        Args:
            config: configuration for scanner

        Returns:
            scanner_names: Either None or a list of scanners defined in the policy
        """
        scanner_names = get_policy_filters(config['policy'] if "policy" in config else get_policy_filters(config["filters"]))
        return scanner_names

    def _initialize_input_scanners(self) -> None:
        """Initializes the input filters and sanitizers"""
        if self.lgconfig.input.filters:
            policy_filter_names = self._load_policy_scanners(self.lgconfig.input.filters)
            for filter_name in policy_filter_names:
                self.scanners["input"]["filters"].append(
                    input_scanners.get_scanner_by_name(filter_name,self.lgconfig.input.filters[filter_name]))
        elif self._lgconfig.input.sanitizers:
            sanitizer_names = self._lgconfig.input.sanitizers.keys()
            for sanitizer_name in sanitizer_names:
                self.scanners["input"]["sanitizers"].append(
                    input_scanners.get_scanner_by_name(sanitizer_name,self.lgconfig.input.sanitizers[sanitizer_name]))
        else:
            logger.error("Error initializing filters")
    
    
    def _initialize_output_scanners(self) -> None:
        """Initializes output filters and sanitizers"""
        if self.lgconfig.output.filters:
            policy_filter_names = self._load_policy_scanners(self.lgconfig.output.filters)
            for filter_name in policy_filter_names:
                self.scanners["output"]["filters"].append(
                    output_scanners.get_scanner_by_name(filter_name,self.lgconfig.output.filters[filter_name]))
        elif self.lgconfig.output.sanitizers:
            sanitizer_names = self.lgconfig.output.sanitizers.keys()
            for sanitizer_name in sanitizer_names:
                self.scanners["input"]["sanitizers"].append(
                    input_scanners.get_scanner_by_name(sanitizer_name,self.lgconfig.output.sanitizers[sanitizer_name]))
        else:
            logger.error("Error initializing filters")

    def __init_scanners(self) -> None:
         """Initializes input and output scanners"""
         if self.lgconfig.input:
             self._initialize_input_scanners()
         if self.lgconfig.output:
             self._initialize_output_scanners()

    def _apply_input_filters(self,input_prompt) -> dict[str,dict[str,Any]]:
        """Takes in input_prompt and applies filters on it
        
        Args:
            input_prompt: The prompt to apply filters on

        Returns:
            result: A dictionary with key as scanner_name which is the name of the scanner applied to the input and value as a dictionary with keys "sanitized_prompt" which is the actual prompt,
                    "is_valid" which is boolean that says if the prompt is valid or not based on a scanner applied and "risk_score" which gives the risk score assigned by the scanner to the prompt. 
        """
        result = {}
        for scanner in self.scanners["input"]["filters"]:
            sanitized_prompt, is_valid, risk_score = scanner.scan(input_prompt)
            scanner_name = type(scanner).__name__
            result[scanner_name] = {
                "sanitized_prompt": sanitized_prompt,
                "is_valid": is_valid,
                "risk_score": risk_score,
            }

        return result    
    

    def _apply_input_sanitizers(self,input_prompt) -> dict[str,dict[str,Any]]:
        """Takes in input_prompt and applies sanitizers on it
        
        Args:
            input_prompt: The prompt to apply filters on

        Returns:
            result: A dictionary with key as scanner_name which is the name of the scanner applied to the input and value as a dictionary with keys "sanitized_prompt" which is the actual prompt,
                    "is_valid" which is boolean that says if the prompt is valid or not based on a scanner applied and "risk_score" which gives the risk score assigned by the scanner to the prompt. 
        """
        result = scan_prompt(self.scanners["input"]["sanitizers"], input_prompt)
        return result
    
    def _apply_output_filters(self,original_input,model_response) -> dict[str,dict[str,Any]]:
        """Takes in model_response and applies filters on it
        
        Args:
            original_input: The original input prompt for which model produced a response

        Returns:
            result: A dictionary with key as scanner_name which is the name of the scanner applied to the output and value as a dictionary with keys "sanitized_prompt" which is the actual prompt,
                    "is_valid" which is boolean that says if the prompt is valid or not based on a scanner applied and "risk_score" which gives the risk score assigned by the scanner to the prompt. 
        """
        result = {}
        for scanner in self.scanners["output"]["filters"]:
            sanitized_prompt, is_valid, risk_score = scanner.scan(original_input, model_response)
            scanner_name = type(scanner).__name__
            result[scanner_name] = {
                "sanitized_prompt": sanitized_prompt,
                "is_valid": is_valid,
                "risk_score": risk_score,
            }
        return result
    
    def _apply_output_sanitizers(self, input_prompt, model_response) -> dict[str,dict[str,Any]]:
        """Takes in model_response and applies sanitizers on it
        
        Args:
            original_input: The original input prompt for which model produced a response

        Returns:
            result: A dictionary with key as scanner_name which is the name of the scanner applied to the output and value as a dictionary with keys "sanitized_prompt" which is the actual prompt,
                    "is_valid" which is boolean that says if the prompt is valid or not based on a scanner applied and "risk_score" which gives the risk score assigned by the scanner to the prompt. 
        """
        result = scan_output(self.scanners["output"]["sanitizers"], input_prompt, model_response)
        return result
    
    
    def _apply_policy_input(self,result_scan)-> tuple[bool,str,dict[str,Any]]:
        """Applies policy on input
        
        Args:
            result_scan: A dictionary of results of scanners on input

        Returns:
            tuple with first element being policy decision (true or false), policy_message as the message sent by policy and result_scan a dict with all the scan results.
        """
        policy_expression = self.lgconfig.input.filters['policy'] if 'policy' in self.lgconfig.input.filters else " and ".join(list(self.lgconfig.input.filters))
        policy_message = self.lgconfig.input.filters['policy_message'] if 'policy_message' in self.lgconfig.input.filters else "Request Forbidden"
        policy = GuardrailPolicy()
        if not policy.evaluate(policy_expression, result_scan):
            return False, policy_message, result_scan
        return True, policy_message, result_scan

    def _apply_policy_output(self,result_scan) -> tuple[bool,str,dict[str,Any]]:
        """Applies policy on output
        
        Args:
            result_scan: A dictionary of results of scanners on output

        Returns:
            tuple with first element being policy decision (true or false), policy_message as the message sent by policy and result_scan a dict with all the scan results.
        """
        policy_expression = self.lgconfig.output.filters['policy'] if 'policy' in self.lgconfig.output.filters else " and ".join(list(self.lgconfig.output.filters))
        policy_message = self.lgconfig.output.filters['policy_message'] if 'policy_message' in self.lgconfig.output.filters else "Request Forbidden"
        policy = GuardrailPolicy()
        if not policy.evaluate(policy_expression, result_scan):
            return False, policy_message, result_scan
        return True, policy_message, result_scan