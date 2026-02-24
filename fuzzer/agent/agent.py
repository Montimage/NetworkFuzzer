"""Pre-built LangGraph ReAct agent with all NetworkFuzzer tools.

Usage:
    from langchain_openai import ChatOpenAI
    from fuzzer.agent.agent import create_networkfuzzer_agent

    agent = create_networkfuzzer_agent(ChatOpenAI(model="gpt-4"))
    result = agent.invoke({"messages": [("user", "List available attack profiles")]})
"""

import warnings
from typing import Optional

from langchain_core.language_models import BaseChatModel

from langgraph.prebuilt import create_react_agent

from fuzzer.agent.tools import create_networkfuzzer_tools

SYSTEM_PROMPT = """\
You are a NetworkFuzzer assistant — an expert in network protocol security testing.

You have access to NetworkFuzzer, a tool suite for evaluating network components through \
traffic fuzzing, replay, and synthetic generation. Your primary protocol expertise is DICOM \
(medical imaging), but the framework supports TCP, UDP, SCTP, and HTTP2.

## Tool Selection Guide

- **fuzz_with_rl**: Use for deep, intelligent vulnerability discovery against a live server. \
RL learns which mutations trigger deeper code paths. Start with 'hybrid' mode for maximum coverage. \
Requires a running target server.

- **generate_traffic**: Use for bulk generation of malicious PCAP files without needing a live \
target. Choose 'attack' mode with a specific profile (e.g. 'cve_payloads', 'abort_injection') \
for targeted attacks, or 'smart' mode for feedback-guided generation.

- **replay_traffic**: Use to replay existing PCAP files against a target, optionally applying \
mutation rules. Good for regression testing or replaying previously captured attack traffic.

- **compile_fuzz_rule**: Use when you have an XML rule file that needs compilation before use \
with replay_traffic.

- **list_capabilities**: Use first to discover available protocols, attack profiles, and fuzzing \
modes before launching an attack campaign.

## Workflow Tips

1. Start with list_capabilities to understand what's available.
2. For quick results: generate_traffic with an attack profile, then replay_traffic the output.
3. For thorough testing: fuzz_with_rl in hybrid mode with 10000+ timesteps.
4. Always check output paths in results — they contain generated PCAPs for further analysis.
"""


def create_networkfuzzer_agent(
    llm: BaseChatModel,
    project_root: Optional[str] = None,
) -> object:
    """Create a LangGraph ReAct agent with all NetworkFuzzer tools.

    Args:
        llm: A LangChain chat model (e.g. ChatOpenAI, ChatAnthropic).
        project_root: Path to NetworkFuzzer project root. Auto-detected if None.

    Returns:
        A LangGraph CompiledGraph that can be invoked with messages.
    """
    tools = create_networkfuzzer_tools(project_root=project_root)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return create_react_agent(llm, tools, prompt=SYSTEM_PROMPT)


def run_standalone(
    query: str,
    model: str = "gpt-4",
    project_root: Optional[str] = None,
) -> str:
    """Run a single query against the NetworkFuzzer agent.

    Convenience function for quick testing without setting up an orchestrator.

    Args:
        query: Natural language query (e.g. "List available attack profiles").
        model: OpenAI model name to use.
        project_root: Path to NetworkFuzzer project root.

    Returns:
        The agent's final text response.
    """
    from langchain_openai import ChatOpenAI

    llm = ChatOpenAI(model=model)
    agent = create_networkfuzzer_agent(llm, project_root=project_root)
    result = agent.invoke({"messages": [("user", query)]})
    # Extract the last AI message
    messages = result.get("messages", [])
    for msg in reversed(messages):
        if hasattr(msg, "content") and msg.content and not hasattr(msg, "tool_calls"):
            return msg.content
    return str(result)


if __name__ == "__main__":
    import sys

    query = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "List available attack profiles"
    print(run_standalone(query))
