
from mcpgateway.services.logging_service import LoggingService
from llmguardplugin.schema import LLMGuardConfig, ModeConfig
from llmguardplugin.policy import GuardrailPolicy, get_policy_filters
from typing import Any, Generic, Optional, Self, TypeVar

from llm_guard import input_scanners, output_scanners
from llm_guard import scan_output, scan_prompt

logging_service = LoggingService()
logger = logging_service.get_logger(__name__)

class LLMGuardBase():
    def __init__(self, config: Optional[dict[str, Any]]) -> None:
        self._lgconfig = LLMGuardConfig.model_validate(config)
        self._scanners = {"input": {"sanitizers": [], "filters" : []}, "output": {"sanitizers": [], "filters" : []}}
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
            logger.info(f"Shriti Processing config {self._lgconfig}")
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
    
    def _apply_policy_input(self,result_scan):
        policy_expression = self._lgconfig.input.filters['policy'] if 'policy' in self._lgconfig.input.filters else " and ".join(list(self._lgconfig.input.filters))
        policy_message = self._lgconfig.input.filters['policy_message'] if 'policy_message' in self._lgconfig.input.filters else "Request Forbidden"
        policy = GuardrailPolicy()
        if not policy.evaluate(policy_expression, result_scan):
            return False, policy_message, result_scan
        return True, policy_message, result_scan

    def _apply_policy_output(self,result_scan):
        policy_expression = self._lgconfig.output.filters['policy'] if 'policy' in self._lgconfig.output.filters else " and ".join(list(self._lgconfig.output.filters))
        policy_message = self._lgconfig.output.filters['policy_message'] if 'policy_message' in self._lgconfig.output.filters else "Request Forbidden"
        policy = GuardrailPolicy()
        if not policy.evaluate(policy_expression, result_scan):
            return False, policy_message, result_scan
        return True, policy_message, result_scan