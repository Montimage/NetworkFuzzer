"""NetworkFuzzer LangChain sub-agent.

Provides LangChain-compatible tools for driving NetworkFuzzer from
an LLM orchestrator or parent pentesting agent.

Quick start:
    from fuzzer.agent.tools import create_networkfuzzer_tools
    tools = create_networkfuzzer_tools()

    # Or use the pre-built agent:
    from fuzzer.agent.agent import create_networkfuzzer_agent
    agent = create_networkfuzzer_agent(llm)
"""

def __getattr__(name):
    if name == "create_networkfuzzer_tools":
        from fuzzer.agent.tools import create_networkfuzzer_tools
        return create_networkfuzzer_tools
    if name == "create_networkfuzzer_agent":
        from fuzzer.agent.agent import create_networkfuzzer_agent
        return create_networkfuzzer_agent
    raise AttributeError(f"module 'fuzzer.agent' has no attribute {name!r}")

__all__ = ["create_networkfuzzer_tools", "create_networkfuzzer_agent"]
