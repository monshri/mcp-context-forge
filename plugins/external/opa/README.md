# OPA Plugin for MCP Gateway

> Author: Shriti Priya
> Version: 0.1.0

An OPA plugin that enforces rego policies on requests and allows/denies requests as per policies.

The OPA plugin is composed of two components:
1. OPA server 
2. The pre/post hooks on tools/prompts for OP.  A plugin behaving as OPA client and calling the OPA server.

### OPA Server
To define a policy file you need to go into opaserver/rego and create a sample policy file for you. 
Example -`example.rego` is present.
Once you have this file created in this location, when building the server, the opa binaries will be downloaded and a container will be build. 
In the `run_server.sh` file, the opa server will run as a background service in the container with the rego policy file.

### OPA Plugin 
The OPA plugin runs as an external plugin with pre/post tool invocations. So everytime, a tool invocation is made, and
if OPAPluginFilter has been defined in config.yaml file, the tool invocation will pass through this OPA Plugin.


## Installation

1. Copy .env.example .env
2. Enable plugins in `.env` using `PLUGINS_ENABLED=true`
3. Add the plugin configuration to `plugins/config.yaml`:

```yaml
plugins:
  - name: "OPAPluginFilter"
    kind: "opapluginfilter.plugin.OPAPluginFilter"
    description: "An OPA plugin that enforces rego policies on requests and allows/denies requests as per policies"
    version: "0.1.0"
    author: "Shriti Priya"
    hooks: ["prompt_pre_fetch", "prompt_post_fetch", "tool_pre_invoke", "tool_post_invoke"]
    tags: ["plugin"]
    mode: "enforce"  # enforce | permissive | disabled
    priority: 10
    applied_to:
      tools:
        - name: "fast-time-git-status"
          context:
            - "global.opa_policy_context.git_context"
          extensions:
            policy: "example"
            policy_endpoint: "allow"
    conditions:
      # Apply to specific tools/servers
      - server_ids: []  # Apply to all servers
        tenant_ids: []  # Apply to all tenants
    config:
      # Plugin config dict passed to the plugin constructor
      opa_base_url: "http://127.0.0.1:8181/v1/data/"
```
The `applied_to` key in config.yaml, has been used to selectively apply policies and provide context for a specific tool. 

In the example above:
```applied_to:
      tools:
        - name: "fast-time-git-status"
          context:
            - "global.opa_policy_context.git_context"
          extensions:
            policy: "example"
            policy_endpoint: "allow"
```

Here, using this, you can provide the `name` of the tool you want to apply policy on, you can also provide 
context to the tool with the prefix `global` if it needs to check the context in global context provided. 
The key `opa_policy_context` is used to get context for policies and you can have multiple contexts within this key using `git_context` key.
You can also provide policy within the `extensions` key where you can provide information to the plugin
related to which policy to run and what endpoint to call for that policy.
In the `config` key in `config.yaml` file OPAPlugin consists of the following things:
`opa_base_url` : It is the base url on which opa server is running.

## Testing



## License

Apache-2.0

## Support

For issues or questions, please open an issue in the MCP Gateway repository.

















