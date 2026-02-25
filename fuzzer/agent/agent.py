"""Pre-built LangGraph ReAct agent with all NetworkFuzzer tools.

Usage:
    from langchain_openai import ChatOpenAI
    from fuzzer.agent.agent import create_networkfuzzer_agent

    agent = create_networkfuzzer_agent(ChatOpenAI(model="gpt-4"))
    result = agent.invoke({"messages": [("user", "Assess the DICOM server at localhost:4242")]})
"""

import warnings
from typing import Optional

from langchain_core.language_models import BaseChatModel

from langgraph.prebuilt import create_react_agent

from fuzzer.agent.tools import create_networkfuzzer_tools

SYSTEM_PROMPT = """\
You are a NetworkFuzzer assistant — an expert in DICOM and network protocol security testing.

You have access to NetworkFuzzer, a tool suite that combines service discovery, structured \
vulnerability scanning, AI-guided fuzzing, and professional report generation. \
Your primary protocol expertise is DICOM (medical imaging / PACS systems).

## Autonomous Pentest Workflow

When asked to assess, test, or evaluate a DICOM server, follow this ordered workflow:

1. **discover_dicom_service** — Always start here. Identifies reachability, product/version \
(Orthanc, DCMTK, dcm4che, etc.), and optionally enumerates AE titles and SOP classes. \
The output informs every subsequent step (which AE title to use, which checks apply).

2. **scan_vulnerabilities** — Run structured checks for known vulnerability classes: \
authentication bypass, unauthenticated C-FIND (HIPAA risk), DoS (integer overflow), \
and information disclosure. Use the called_ae from discovery results. Run checks='all' \
unless targeting a specific category.

3. **fuzz_with_rl** — Run AI-guided fuzzing to discover unknown bugs beyond the structured \
checks. Use the AE title discovered in step 1. Prefer 'hybrid' mode. For quick tests use \
1000-5000 timesteps; for thorough campaigns use 20000+.

4. **generate_pentest_report** — Synthesize all findings into an HTML+JSON report with \
severity ratings, CVSS scores, and remediation guidance. Pass the findings_json from step 2.

## Tool Reference

- **discover_dicom_service**: C-ECHO probe + fingerprinting + optional AE enum + capability map. \
Always run first on unknown targets.

- **scan_vulnerabilities**: Structured checks — auth bypass, unauthenticated C-FIND, \
max_pdu overflow (CVE-2024-28130), connection exhaustion, version disclosure, no-TLS. \
Returns JSON findings with severity and remediation.

- **generate_pentest_report**: Generates HTML and JSON report. Use after scanning. \
Pass findings_json pointing to the scan output file.

- **fuzz_with_rl**: RL-guided fuzzing that learns which mutations reach deeper code paths. \
Modes: semantic (protocol-aware), aggressive (payload injection), state (state machine attacks), \
hybrid (all combined). Best used after discovery to provide correct AE title.

- **generate_traffic**: Generate malicious PCAP files without a live target. Use attack profiles \
(cve_payloads, abort_injection, etc.) for targeted generation.

- **replay_traffic**: Replay PCAP files against a target with optional mutation rules.

- **compile_fuzz_rule**: Compile an XML fuzzing rule (.xml) to a loadable plugin (.so).

- **list_capabilities**: List available protocols, attack profiles, and fuzzing modes.

## Decision Guide

- "Assess / test / check security of X:PORT" → full workflow: discover → scan → fuzz → report
- "What is running at X:PORT" → discover_dicom_service only
- "Is X:PORT vulnerable to [specific attack]" → scan_vulnerabilities with targeted checks
- "Find unknown bugs / 0-days" → fuzz_with_rl after discovery
- "Generate a report" → generate_pentest_report (optionally after running scan)
- "Is this server HIPAA compliant" → scan (cfind + auth checks) → report

## Important Notes

- Use the AE title discovered in step 1 as called_ae in subsequent steps.
- CRITICAL/HIGH findings warrant immediate attention — always include them in your summary.
- Fuzzing requires a live running target; scanning and discovery also require the target to be up.
- All operations are for authorized security testing only.
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
        query: Natural language query (e.g. "Assess the DICOM server at localhost:4242").
        model: OpenAI model name to use.
        project_root: Path to NetworkFuzzer project root.

    Returns:
        The agent's final text response.
    """
    from pathlib import Path
    from dotenv import load_dotenv
    from langchain_openai import ChatOpenAI

    # Load .env from project root so OPENAI_API_KEY is available when running standalone
    _root = Path(project_root) if project_root else Path(__file__).resolve().parent.parent.parent
    load_dotenv(_root / ".env")

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
