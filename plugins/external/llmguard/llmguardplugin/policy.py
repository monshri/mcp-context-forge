
import ast
import re
import warnings
from enum import Enum
from typing import Union

warnings.simplefilter("ignore")


class ResponseGuardrailPolicy(Enum):
    DEFAULT_NORESPONSE_GUARDRAIL = "I'm sorry, I'm afraid I can't do that."
    DEFAULT_NOSKILL = "No skill provided to apply guardrails"
    DEFAULT_JAILBREAK = "Stop trying to jailbreak. I am a responsible assistant."
    DEFAULT_NOCONFIG = "No guardrails configuration provided"


class GuardrailPolicy:
    def evaluate(self, policy: str, scan_result: dict) -> Union[bool, str]:
        policy_variables = {key: value['is_valid'] for key, value in scan_result.items()}
        if isinstance(policy, bool):
            return False
        try:
            # Parse the policy expression into an abstract syntax tree
            tree = ast.parse(policy, mode='eval')
            # Check if the tree only contains allowed operations
            for node in ast.walk(tree):
                if isinstance(node, (ast.BinOp, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow)):
                    continue
                elif isinstance(node, (ast.Num, ast.UnaryOp)):
                    continue
                elif isinstance(node, (ast.Expression)):
                    continue
                elif isinstance(node, (ast.BoolOp, ast.Or, ast.And)):
                    continue
                elif isinstance(node, (ast.Name, ast.Eq, ast.Compare, ast.Load)):
                    continue
                else:
                    raise ValueError("Invalid operation")

            # Evaluate the expression
            return eval(compile(tree, '<string>', 'eval'), {}, policy_variables)
        except (ValueError, SyntaxError, Exception):
            return "Invalid expression"


def word_wise_levenshtein_distance(sentence1, sentence2):
    words1 = sentence1.split()
    words2 = sentence2.split()

    n, m = len(words1), len(words2)
    dp = [[0] * (m + 1) for _ in range(n + 1)]

    for i in range(n + 1):
        dp[i][0] = i
    for j in range(m + 1):
        dp[0][j] = j

    for i in range(1, n + 1):
        for j in range(1, m + 1):
            if words1[i - 1] == words2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                dp[i][j] = min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]) + 1

    return dp[n][m]


def get_policy_filters(policy_expression):
    if isinstance(policy_expression, str):
        pattern = r"\b(and|or|not)\b|[()]"
        filters = re.sub(pattern, "", policy_expression).strip()
        return filters.split()
    elif isinstance(policy_expression, dict):
        filters = list(policy_expression.keys())
        return filters
    else:
        return None


def initialize_guardrail_context():
    guardrails_context = {
        "guardrails": {"input": {"filters": [], "sanitizers": []}, "output": {"filters": [], "sanitizers": []}}
    }
    return guardrails_context


def parse_granite_output(output):
    safe = "Yes"
    unsafe = "No"
    label = None
    confidence_level = None
    result = output.split("\n")
    if len(result) > 1:
        match = re.search(r'<confidence>(.*?)</confidence>', result[1])
        if match:
            confidence_level = match.group(1).strip()
        else:
            confidence_level = None
    if unsafe.lower() == result[0].lower():
        label = unsafe
    elif safe.lower() == result[0].lower():
        label = safe
    else:
        label = "Failed"

    return label, confidence_level