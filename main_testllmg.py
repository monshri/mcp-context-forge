import asyncio

# First-Party
from mcpgateway.plugins.framework.manager import PluginManager
from mcpgateway.plugins.framework.models import GlobalContext, PromptPrehookPayload

from mcpgateway.models import Message, PromptResult, Role, TextContent

from mcpgateway.plugins.framework.models import (
    PluginContext,
    GlobalContext,
    PromptPosthookPayload,
    PromptPrehookPayload,
)


async def main():
    manager = PluginManager("/Users/shritipriya/Documents/sept@229-pr/backup/mcp-context-forge/plugins/config.yaml")
    import pdb
    pdb.set_trace()
    await manager.initialize()
    prompt = PromptPrehookPayload(name="test_prompt", args={"user": "What a crapshow!"})
    global_context = GlobalContext(request_id="1", server_id="2")
    result, contexts = await manager.prompt_pre_fetch(prompt, global_context=global_context)
    print(result)
    messages = [
            Message(role=Role.USER, content=TextContent(type="text", text="fuck off")),
        ]

    prompt_result = PromptResult(messages=messages)

    payload_result = PromptPosthookPayload(name="test_prompt", result=prompt_result)

    result, _ = await manager.prompt_post_fetch(payload_result, global_context=global_context, local_contexts=contexts)
    print(result)

    await manager.shutdown()


asyncio.run(main())