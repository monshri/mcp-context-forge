# LLMGuardPlugin
A plugin that utilizes the llmguard library's functionality to implement safety controls for both incoming and outgoing prompts.

## Guardrails
Guardrails are protective protocols and standards implemented to ensure that AI agents and large language models (LLMs) do not produce or encourage dangerous, harmful, or inaccurate content. These protective measures aim to reduce various risks linked to LLM usage, including prompt manipulation attacks, security bypasses, misinformation dissemination, toxic content generation, misleading information, and unauthorized data exposure


## LLMGuardPlugin 

**File:** `mcp-context-forge/plugins/external/llmguard/llmguardplugin/plugin.py`

Core functionalities:

- Filters (boolean allow or deny) and Sanitizers (transformations on the prompt) guardrails on input and model or output responses
- Customizable policy with logical combination of filters
- Policy driven scanner initialization
- Time-based expiration controls for individual plugins and cross-plugin vault lifecycle management
- Additional Vault leak detection protection 


Under the ``plugins/external/llmguard/llmguardplugin/`` directory, you will find ``plugin.py`` file implementing the hooks for `prompt_pre_fetch` and `prompt_post_fetch`. 
In the file `llmguard.py` the base class `LLMGuardBase()` implements core functionalities of input and output sanitizers & filters utilizing the capabilities of the open-source guardrails library `llmguard`.

### Plugin Initialization and Configuration

A typical configuration file for the plugin looks something like this:


```yaml

    config:
          cache_ttl: 120 #defined in seconds
          input:
            sanitizers:
              Anonymize:
                language: "en"
                vault_ttl: 120 #defined in seconds
                vault_leak_detection: True
          output:
            sanitizers:
              Deanonymize:
                matching_strategy: exact
```

  
As part of plugin initialization, an instance of `LLMGuardBase()`, `CacheTTLDict()` is initailized. The configurations defined for the plugin are validated, and if none of the `input` or `output` keys are defined in the config, the plugin throws a `PluginError` with message `Invalid configuration for plugin initilialization`.
The initialization of `LLMGuardBase()` instance initializes all the filters and scanners defined under the `config` key of plugin using the member functions of `LLMGuardBase()`: `_initialize_input_filters()`
,`_initialize_output_filters()`,`_initialize_input_sanitizers()` and `_initialize_output_sanitizers()`. 


The config key is a nested dictionary structure that consists of configuration of the guardrail. The config can have two modes input and output. Here, if input key is non-empty guardrail is applied to the original input prompt entered by the user and if output key is non-empty then guardrail is applied on the model response that comes after the input has been passed to the model. You can choose to apply, only input, output or both for your use-case.

Under the input or output keys, we have two types of guards that could be applied:

- **filters**: They reject or allow input or output, based on policy defined in the policy key for a filter. Their return type is boolean, to be True or False. They do not apply transformation on the input or output.
  You define the guards that you want to use within the filters key:

```yaml
  filters:
    filter1:
      filter1_config1: <configuration for filter1>
      ...
    filter2:
      filter2_config1: <configuration for filter2>
      ...
    policy: <your custom policy using filter1 and filter2>
    policy_message: <your custom policy message>
```

Once, you have done that, you can apply logical combinations of that filters using and, or, parantheses etc. The filters will be applied according to this policy. For performance reasons, only those filters will be initialized that has been defined in the policy, if no policy has been defined, then by default a logical and of all the filters will be applied as a default policy. The framework also gives you the liberty to define your own custom policy_message for denying an input or output.

- **sanitizers**: They basically transform an input or output. The sanitizers that have been defined would be applied sequentially to the input.

As part of initialization of input and output filters, for which `policy` could be defined, the filters are initialised for only those filters which has been used in the policy. If filters has been defined under the `filters` key and not defined under the `policy` key, that filter will not be loaded. If no `policy` has been defined, then a default and combination of defined filters will be used for policy. For sanitizers, there is no policy so whatever is defined under the `sanitizer` key, that gets initialized. Once, all the filters and sanitizers have been successfully initialized by the plugin as per the configuration, the plugin is ready to accept any prompt and pass these filters and sanitizers on it.


### Plugin based Filtering and Sanitization

Once the plugin is initialized and ready, you would see the following message in the plugin server logs:

#NOTE: Add picture here of server

The main functions which implement the input and output guardrails are:

1. _apply_input_filters() - Applies input filters to the input and after the filters or guardrails have been applied, the result is evaluated against the policy using `LLMGuardBase()._apply_policy_input()`. If the decision of the policy is deny (False), then the plugin throws a `PluginViolationError` with description and details on why the policy was denied. The description also contains the type of threat, example, `PromptInjection` detected in the prompt, etc. The filters don't transform the payload. 
2. _apply_input_sanitizers() - Applies input sanitizers to the input. For example, in case an `Anonymize` was defined in the sanitizer, so an input "My name is John Doe" after the sanitizers have been applied will result in "My name is [REDACTED_PERSON_1]" will be stored as part of modified_payload in the plugin.
3. _apply_output_filters() - Applies input filters to the input and after the filters or guardrails have been applied, the result is evaluated against the policy using `LLMGuardBase()._apply_policy_output()`. If the decision of the policy is deny (False), then the plugin throws a `PluginViolationError` with description and details on why the policy was denied. The description also contains the type of threat, example, `Toxicity` detected in the prompt, etc. The filters don't transform the result.
4. _apply_output_sanitizers() - Applies input sanitizers to the input. For example, in case an `Deanonymize` was defined in the sanitizer, so an input "My name is [REDACTED_PERSON_1]" after the sanitizers have been applied will result in "My name is John Doe" will be stored as part of modified_payload in the plugin.


The filters and sanitizers that could be applied on inputs are:

* ``sanitizers``: ``Anonymize``, ``Regex`` and ``Secrets``.
* ``filters``: ``BanCode``, ``BanCompetitors``, ``BanSubstrings``, ``BanTopics``,
``Code``, ``Gibberish``, ``InvisibleText``, ``Language``, ``PromptInjection``, ``Regex``,
``Secrets``, ``Sentiment``, ``TokenLimit`` and ``Toxicity``.

The filters and sanitizers that could be applied on outputs are:

* ``sanitizers``: ``Regex``, ``Sensitive``, and ``Deanonymize``.
* ``filters``: ``BanCode``, ``BanCompetitors``, ``BanSubstrings``, ``BanTopics``, ``Bias``, ``Code``, ``JSON``, ``Language``, ``LanguageSame``,
``MaliciousURLs``, ``NoRefusal``, ``ReadingTime``, ``FactualConsistency``, ``Gibberish``
``Regex``, ``Relevance``, ``Sentiment``, ``Toxicity`` and ``URLReachability``


A typical example of applying input and output filters:

``config-input-output-filters.yaml``

```yaml

plugins:
  
  # Self-contained LLMGuardPluginFilter
  - name: "LLMGuardPluginFilter"
    kind: "llmguardplugin.plugin.LLMGuardPlugin"
    description: "A plugin for running input through llmguard scanners "
    version: "0.1"
    author: "MCP Context Forge Team"
    hooks: ["prompt_pre_fetch", "prompt_post_fetch"]
    tags: ["plugin", "transformer", "llmguard", "regex", "pre-post"]
    mode: "enforce"  # enforce | permissive | disabled
    priority: 10
    conditions:
      # Apply to specific tools/servers
      - prompts: ["test_prompt"]
        server_ids: []  # Apply to all servers
        tenant_ids: []  # Apply to all tenants
    config:
      input:
        filters:
          PromptInjection:
            threshold: 0.6
            use_onnx: false
          policy: PromptInjection
          policy_message: I'm sorry, I cannot allow this input.
        sanitizers:
          Anonymize:
            language: "en"
            vault_ttl: 120 #defined in seconds
            vault_leak_detection: True
      output:
        filters:
          Toxicity:
              threshold: 0.5
          policy: Toxicity
          policy_message: I'm sorry, I cannot allow this output.
        sanitizers:
          Deanonymize:
            matching_strategy: exact
```

# Policy `mcp-context-forge/plugins/external/llmguard/llmguardplugin/policy.py`


`GuardrailPolicy` : This class implements the policy evaluation system for the LLMGuardPlugin. Basically, after the input prompt or model response has been passed through input or output filters, if there is a policy_expression or `policy` defined for input or output section of config, it's evaluated using this class.
Your `policy` could be any logical combination (with parantheses) of filters and this class `GuardrailPolicy` would be used to evaluate it.

For example in `mcp-context-forge/plugins/external/llmguard/examples/config-complex-policy.yaml`
```yaml
    config:
      input:
        filters:
          PromptInjection:
            threshold: 0.8
            use_onnx: false
          Toxicity:
            threshold: 0.5
          TokenLimit:
            limit: 4096
          policy: (PromptInjection and Toxicity) and TokenLimit
      output:
        filters:
          Toxicity:
            threshold: 0.5
          Regex:
            patterns:
              - 'Bearer [A-Za-z0-9-._~+/]+'
            is_blocked: True
            redact: False
          policy: Toxicity and Regex
```

# Guardrails Context
The input or output when passed through guardrails a context is added for the filters or sanitizers ran on the input or output. Also, if there are any context that needs to be passed to other plugins. 
For example - In the case of Anonymizer and Deanonymizer, in `context.state` or `context.global_context.state`, within the key `guardrails` information like original prompt, id of the vault used for anonymization etc is passed. This context is either utilized within the plugin or passed to other plugins. If you want to pass the filters or scanners information in context, just enable it in config using ` set_guardrails_context: True`.p 


## Schema

**File:** `mcp-context-forge/plugins/external/llmguard/llmguardplugin/schema.py`

### ModeConfig Class

The `ModeConfig` class defines the configuration schema for individual guardrail modes (input or output processing):

- **sanitizers**: Optional dictionary containing transformers that modify the original input/output content. These components actively change the data (e.g., removing sensitive information, redacting PII)

- **filters**: Optional dictionary containing validators that return boolean results without modifying content. These determine whether content should be allowed or blocked (e.g., toxicity detection, prompt injection detection)

The example shows how filters can be configured with thresholds: `{"PromptInjection" : {"threshold" : 0.5}}` sets a 50% confidence threshold for detecting prompt injection attempts.

### LLMGuardConfig Class

The `LLMGuardConfig` class serves as the main configuration container with three key attributes:

- **cache_ttl**: Integer specifying cache time-to-live in seconds (defaults to 0, meaning no caching). This controls how long guardrail results are cached to improve performance

- **input**: Optional `ModeConfig` instance defining sanitizers and filters applied to incoming prompts/requests

- **output**: Optional `ModeConfig` instance defining sanitizers and filters applied to model responses
- **set_guardrail_context**: If true, the context is set in the plugins



# LLMGuardPlugin Cache

**File:** `mcp-context-forge/plugins/external/llmguard/llmguardplugin/cache.py`

## Overview

The cache system solves a critical problem in LLM guardrail architectures: cross-plugin data sharing. When processing user inputs through multiple security layers, plugins often need to share state information. For example, an Anonymizer plugin might replace PII with tokens, and later a Deanonymizer plugin needs the original mapping to restore the data.

## CacheTTLDict Class

The CacheTTLDict class extends Python's built-in dict interface while providing Redis-backed persistence with automatic expiration.

### Key Features

- **TTL Management**: Automatic key expiration using Redis's built-in TTL functionality
- **Redis Integration**: Uses Redis as the backend storage for scalability and persistence across processes
- **Serialization**: Uses Python's pickle module to serialize complex objects (tuples, dictionaries, custom objects)
- **Comprehensive Logging**: Detailed logging for debugging and monitoring cache operations

## Configuration

The system uses environment variables for Redis connection:

- `REDIS_HOST`: Redis server hostname (defaults to "redis")
- `REDIS_PORT`: Redis server port (defaults to 6379)

This follows containerized deployment patterns where Redis runs as a separate service.

## Core Methods

### update_cache(key, value)

Updates the cache with a key-value pair and sets TTL:

- Serializes the value using `pickle.dumps()` to handle complex Python objects
- Stores the serialized data in Redis using `cache.set()`
- Sets expiration using `cache.expire()` - Redis automatically removes the key after TTL expires
- Returns a tuple indicating success of both set and expire operations

### retrieve_cache(key)

Retrieves and deserializes cached data:

- Fetches raw data from Redis using `cache.get()`
- Deserializes using `pickle.loads()` to restore the original Python object
- Handles cache misses gracefully by returning None

### delete_cache(key)

Explicitly removes cache entries:

- Deletes the key using `cache.delete()`
- Verifies deletion by checking both the delete count and key existence
- Logs the operation result for monitoring


# Vault Management 
```yaml
    config:
          cache_ttl: 120 #defined in seconds
          input:
            sanitizers:
              Anonymize:
                language: "en"
                vault_ttl: 120 #defined in seconds
                vault_leak_detection: True
          output:
            sanitizers:
              Deanonymize:
                matching_strategy: exact
```
In the above configuration, `cache_ttl` is the key, that is used to determine the expiry time of vault across plugins. So, for cases like `Anonymize` and `Deanonymize` in the input and output filters respectively, if the plugins have been defined in individual plugins, vault information need to be passed in the plugin context. The keys are stored in the cache as above, and after reaching `cache_ttl` it deletes that key from the cache. For sharing cache within the above two plugins, we use redis, which has a configuration by itself, that can set expiry time for a key stored in cache, and automatically deletes itself after the expiry time has reached.

However, there might be a case, where we need to share vault information for the above example within the same plugin, when both input and output  `Anonymize` and `Deanonymize` have been defined within the same plugin, in that case, vault needs to have a ttl. `vault_ttl` is used for that purpose, where an in-memory caching is used, and if the creation time of the vault has reached it's expiry in the current situation, then the vault gets deleted and new vault is assigned within the same plugin, having no history of past interactions.


# Multiple Configurations of LLMGuardPlugin

Sanitizers and Filters could be applied within the same plugin sequentially in configuration file like 
or it could be applied as a separated plugin and be controlled by priority.

1. Input filter, input sanitizer, output filter and output sanitizers within the same plugin
2. Input filter, input sanitizer, output filter and output sanitizers in the separate plugins each

## 1 Input filter, input sanitizer, output filter and output sanitizers within the same plugin

```yaml
    plugins:
      # Self-contained Search Replace Plugin
      - name: "LLMGuardPluginAll"
        kind: "llmguardplugin.plugin.LLMGuardPlugin"
        description: "A plugin for running input and output through llmguard scanners "
        version: "0.1"
        author: "MCP Context Forge Team"
        hooks: ["prompt_pre_fetch","prompt_post_fetch"]
        tags: ["plugin", "transformer", "llmguard", "pre-post"]
        mode: "enforce"  # enforce | permissive | disabled
        priority: 20
        conditions:
          # Apply to specific tools/servers
          - prompts: ["test_prompt"]
            server_ids: []  # Apply to all servers
            tenant_ids: []  # Apply to all tenants
        config:
          cache_ttl: 120 #defined in seconds
          input:
            filters:
                PromptInjection:
                  threshold: 0.6
                  use_onnx: false
                policy: PromptInjection
                policy_message: I'm sorry, I cannot allow this input.
            sanitizers:
              Anonymize:
                language: "en"
                vault_ttl: 120 #defined in seconds
                vault_leak_detection: True
          output:
            sanitizers:
              Deanonymize:
                matching_strategy: exact
            filters:
              Toxicity:
                  threshold: 0.5
              policy: Toxicity
              policy_message: I'm sorry, I cannot allow this output.


    # Plugin directories to scan
    plugin_dirs:
      - "llmguardplugin"

    # Global plugin settings
    plugin_settings:
      parallel_execution_within_band: true
      plugin_timeout: 30
      fail_on_plugin_error: false
      enable_plugin_api: true
      plugin_health_check_interval: 60
```

Here, the input filters, sanitizers, and output sanitizers and filters are applied within the same plugin sequentially.


## 2   Input filter, input sanitizer, output filter and output sanitizers in separate plugins each

```yaml
plugins:
  # Self-contained Search Replace Plugin
  - name: "LLMGuardPluginInputSanitizer"
    kind: "llmguardplugin.plugin.LLMGuardPlugin"
    description: "A plugin for running input through llmguard scanners "
    version: "0.1"
    author: "MCP Context Forge Team"
    hooks: ["prompt_pre_fetch"]
    tags: ["plugin", "transformer", "llmguard", "regex", "pre-post"]
    mode: "enforce"  # enforce | permissive | disabled
    priority: 20
    conditions:
      # Apply to specific tools/servers
      - prompts: ["test_prompt"]
        server_ids: []  # Apply to all servers
        tenant_ids: []  # Apply to all tenants
    config:
      cache_ttl: 120 #defined in seconds
      input:
        sanitizers:
          Anonymize:
            language: "en"
            vault_ttl: 120 #defined in seconds
            vault_leak_detection: True

  - name: "LLMGuardPluginOutputSanitizer"
    kind: "llmguardplugin.plugin.LLMGuardPlugin"
    description: "A plugin for running input through llmguard scanners "
    version: "0.1"
    author: "MCP Context Forge Team"
    hooks: ["prompt_post_fetch"]
    tags: ["plugin", "transformer", "llmguard", "regex", "pre-post"]
    mode: "enforce"  # enforce | permissive | disabled
    priority: 10
    conditions:
      # Apply to specific tools/servers
      - prompts: ["test_prompt"]
        server_ids: []  # Apply to all servers
        tenant_ids: []  # Apply to all tenants
    config:
      cache_ttl: 60 # defined in minutes
      output:
        sanitizers:
          Deanonymize:
            matching_strategy: exact

    # Self-contained Search Replace Plugin
  - name: "LLMGuardPluginInputFilter"
    kind: "llmguardplugin.plugin.LLMGuardPlugin"
    description: "A plugin for running input through llmguard scanners "
    version: "0.1"
    author: "MCP Context Forge Team"
    hooks: ["prompt_pre_fetch"]
    tags: ["plugin", "transformer", "llmguard", "regex", "pre-post"]
    mode: "enforce"  # enforce | permissive | disabled
    priority: 10
    conditions:
      # Apply to specific tools/servers
      - prompts: ["test_prompt"]
        server_ids: []  # Apply to all servers
        tenant_ids: []  # Apply to all tenants
    config:
      input:
        filters:
          PromptInjection:
            threshold: 0.6
            use_onnx: false
          policy: PromptInjection
          policy_message: I'm sorry, I cannot allow this input.

  # Self-contained Search Replace Plugin
  - name: "LLMGuardPluginOutputFilter"
    kind: "llmguardplugin.plugin.LLMGuardPlugin"
    description: "A plugin for running input through llmguard scanners "
    version: "0.1"
    author: "MCP Context Forge Team"
    hooks: ["prompt_post_fetch"]
    tags: ["plugin", "transformer", "llmguard", "regex", "pre-post"]
    mode: "enforce"  # enforce | permissive | disabled
    priority: 20
    conditions:
      # Apply to specific tools/servers
      - prompts: ["test_prompt"]
        server_ids: []  # Apply to all servers
        tenant_ids: []  # Apply to all tenants
    config:
      output:
        filters:
          Toxicity:
              threshold: 0.5
          policy: Toxicity
          policy_message: I'm sorry, I cannot allow this output.

# Plugin directories to scan
plugin_dirs:
  - "llmguardplugin"

# Global plugin settings
plugin_settings:
  parallel_execution_within_band: true
  plugin_timeout: 30
  fail_on_plugin_error: false
  enable_plugin_api: true
  plugin_health_check_interval: 60
```

Here, we have utilized the priority functionality of plugins. Here, we have kept the priority of input filters to be 10 and input sanitizers to be 20, on `prompt_pre_fetch` and priority of output sanitizers to be 10 and output filters to be 20 on `prompt_post_fetch`. This ensures that for an input first the filter is applied, then sanitizers for any transformations on the input. And later in the output, the sanitizers for output is applied first and later the filters on it.

# Misc Examples

In the folder, `mcp-context-forge/plugins/external/llmguard/examples` there are multiple example usages of LLMGuardPlugin.


| Example | File |
|-----------|-------------|
| All the filters and sanitizers within the same plugin | `mcp-context-forge/plugins/external/llmguard/examples/config-all-in-one.yaml`|
| All the filters and sanitizers in separate 4 plugins | `mcp-context-forge/plugins/external/llmguard/examples/config-separate-plugins.yaml`|
| Input and Output filter in separate plugins | `mcp-context-forge/plugins/external/llmguard/examples/config-input-output-filter.yaml`|
| Input and Output sanitizers in separate plugins | `mcp-context-forge/plugins/external/llmguard/examples/config-input-output-sanitizer.yaml`|
| Input and Output filter with complex policies within same plugins  | `mcp-context-forge/plugins/external/llmguard/examples/config-complex-policy.yaml`|

# Test Cases `mcp-context-forge/plugins/external/llmguard/tests/test_llmguardplugin.py`

| Test Case | Description | Validation |
|-----------|-------------|------------|
| test_llmguardplugin_prehook | Tests prompt injection detection on input | Validates that PromptInjection filter successfully blocks malicious prompts attempting to leak credit card information and returns appropriate violation details |
| test_llmguardplugin_posthook | Tests toxicity detection on output | Validates that Toxicity filter successfully blocks toxic language in LLM responses and applies configured policy message |
| test_llmguardplugin_prehook_empty_policy_message | Tests default message handling for input filter | Validates that plugin uses default "Request Forbidden" message when policy_message is not configured in input filters |
| test_llmguardplugin_prehook_empty_policy | Tests default policy behavior for input | Validates that plugin applies AND combination of all configured filters as default policy when no explicit policy is defined |
| test_llmguardplugin_posthook_empty_policy | Tests default policy behavior for output | Validates that plugin applies AND combination of all configured filters as default policy for output filtering |
| test_llmguardplugin_posthook_empty_policy_message | Tests default message handling for output filter | Validates that plugin uses default "Request Forbidden" message when policy_message is not configured in output filters |
| test_llmguardplugin_invalid_config | Tests error handling for invalid configuration | Validates that plugin throws "Invalid configuration for plugin initialization" error when empty config is provided |
| test_llmguardplugin_prehook_sanitizers_redisvault_expiry | Tests Redis cache TTL expiration | Validates that vault cache entries in Redis expire correctly after the configured cache_ttl period, ensuring proper cleanup of shared anonymization data |
| test_llmguardplugin_prehook_sanitizers_invault_expiry | Tests internal vault TTL expiration | Validates that internal vault data expires and reinitializes after the configured vault_ttl period, preventing stale anonymization mappings |
| test_llmguardplugin_sanitizers_vault_leak_detection | Tests vault information leak prevention | Validates that plugin detects and blocks attempts to extract anonymized vault data (e.g., requesting "[REDACTED_CREDIT_CARD_RE_1]") when vault_leak_detection is enabled |
| test_llmguardplugin_sanitizers_anonymize_deanonymize | Tests complete anonymization workflow | Validates end-to-end anonymization of PII data in input prompts and successful deanonymization of LLM responses, ensuring sensitive data protection throughout the pipeline |

## Installation

To install dependencies with dev packages (required for linting and testing):

```bash
make install-dev
```

Alternatively, you can also install it in editable mode:

```bash
make install-editable
```

## Setting up the development environment

1. Copy .env.template .env
2. Enable plugins in `.env`


## Runtime (server)

# Building and Testing

1. `make build` - This builds two images `llmguardplugin` and `llmguardplugin-testing`.
2. `make start` - This starts three docker containers: `redis` for caching, `llmguardplugin` for the external plugin and `llmguardplugin-testing` for running test cases, since `llmguard` library had compatbility issues with some packages in `mcpgateway` so we kept the testing separate.
3. `make stop` - This stops three docker containers: `redis` for caching, `llmguardplugin` for the external plugin and `llmguardplugin-testing`.

**Note:** To enable logging, set `log_cli = true` in `tests/pytest.ini`.


## Code Linting

Before checking in any code for the project, please lint the code.  This can be done using:

```bash
make lint-fix
```

## End to End LLMGuardPlugin with MCP Gateway

1. Add a sample prompt in the prompt tab of MCP gateway.

2. Suppose you are using the following combination of plugin configuration in `mcp-context-forge/plugins/external/llmguard/resources/plugins/config.yaml`

```yaml
    plugins:
      # Self-contained Search Replace Plugin
      - name: "LLMGuardPluginAll"
        kind: "llmguardplugin.plugin.LLMGuardPlugin"
        description: "A plugin for running input and output through llmguard scanners "
        version: "0.1"
        author: "MCP Context Forge Team"
        hooks: ["prompt_pre_fetch","prompt_post_fetch"]
        tags: ["plugin", "transformer", "llmguard", "pre-post"]
        mode: "enforce"  # enforce | permissive | disabled
        priority: 20
        conditions:
          # Apply to specific tools/servers
          - prompts: ["test_prompt"]
            server_ids: []  # Apply to all servers
            tenant_ids: []  # Apply to all tenants
        config:
          cache_ttl: 120 #defined in seconds
          input:
            filters:
                PromptInjection:
                  threshold: 0.6
                  use_onnx: false
                policy: PromptInjection
                policy_message: I'm sorry, I cannot allow this input.
            sanitizers:
              Anonymize:
                language: "en"
                vault_ttl: 120 #defined in seconds
                vault_leak_detection: True
          output:
            sanitizers:
              Deanonymize:
                matching_strategy: exact
            filters:
              Toxicity:
                  threshold: 0.5
              policy: Toxicity
              policy_message: I'm sorry, I cannot allow this output.


    # Plugin directories to scan
    plugin_dirs:
      - "llmguardplugin"

    # Global plugin settings
    plugin_settings:
      parallel_execution_within_band: true
      plugin_timeout: 30
      fail_on_plugin_error: false
      enable_plugin_api: true
      plugin_health_check_interval: 60
```

3. Once, the above config has been set to `mcp-context-forge/plugins/external/llmguard/resources/plugins/config.yaml`. Run `make build` and `make start` to start the llmguardplugin server.

4. Add the following to `plugins/config.yaml` file

```yaml
  - name: "LLMGuardPluginInputFilter"
    kind: "external"
    mode: "enforce"  # Don't fail if the server is unavailable
    priority: 10 # adjust the priority
    mcp:
      proto: STREAMABLEHTTP
      url: http://127.0.0.1:8001/mcp

  - name: "LLMGuardPluginInputSanitizer"
    kind: "external"
    mode: "enforce"  # Don't fail if the server is unavailable
    priority: 20 # adjust the priority
    mcp:
      proto: STREAMABLEHTTP
      url: http://127.0.0.1:8001/mcp

  - name: "LLMGuardPluginOutputFilter"
    kind: "external"
    mode: "enforce"  # Don't fail if the server is unavailable
    priority: 20 # adjust the priority
    mcp:
      proto: STREAMABLEHTTP
      url: http://127.0.0.1:8001/mcp

  - name: "LLMGuardPluginOutputSanitizer"
    kind: "external"
    mode: "enforce"  # Don't fail if the server is unavailable
    priority: 10 # adjust the priority
    mcp:
      proto: STREAMABLEHTTP
      url: http://127.0.0.1:8001/mcp
```

5. Run `make serve`
6. Now when you test from the UI, for example, as the input prompt has been denied by LLMGuardPlugin since it detected prompt injection in it:
![alt text](image.png)

In your make serve logs you get the following errors:

```bash
2025-09-25 17:23:22,267 - mcpgateway - ERROR - Could not retrieve prompt test_prompt: pre_prompt_fetch blocked by plugin LLMGuardPluginInputFilter: deny - I'm sorry, I cannot allow this input. (PromptInjection detected in the prompt)
```

The above log verifies that the input as Prompt Injection was detected.

























