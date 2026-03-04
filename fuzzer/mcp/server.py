"""NetworkFuzzer MCP Server.

Exposes all NetworkFuzzer pentest and fuzzing capabilities as MCP tools.
Works with ANY MCP-compatible LLM client:
  - Claude Code / Claude Desktop
  - Cursor, Windsurf
  - LangChain agents with MCP support
  - Custom agents using the MCP Python SDK

Transport: stdio (default) — launched as subprocess by the MCP client.

Run standalone for testing:
    python3 -m fuzzer.mcp.server

Configure in .mcp.json (Claude Code picks this up automatically):
    {
      "mcpServers": {
        "networkfuzzer": {
          "command": "/path/to/venv-agent/bin/python3",
          "args": ["-m", "fuzzer.mcp.server"],
          "cwd": "/home/strongcourage/NetworkFuzzer"
        }
      }
    }
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Optional

# Load .env before anything else so OPENAI_API_KEY is available if needed
from dotenv import load_dotenv
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
load_dotenv(_PROJECT_ROOT / ".env")

from mcp.server.fastmcp import FastMCP

# FuzzerRunner handles all subprocess calls — same code path as LangChain agent
from fuzzer.agent.runner import FuzzerRunner

runner = FuzzerRunner(project_root=str(_PROJECT_ROOT))

mcp = FastMCP(
    "NetworkFuzzer",
    instructions=(
        "NetworkFuzzer pentest and fuzzing toolkit for DICOM/PACS security assessment. "
        "Recommended workflow: discover → scan → fuzz → report. "
        "Always run networkfuzzer_discover first to identify the target before scanning or fuzzing."
    ),
)


# ---------------------------------------------------------------------------
# Pentest tools
# ---------------------------------------------------------------------------

@mcp.tool()
def networkfuzzer_discover(
    host: str,
    port: int = 4242,
    calling_ae: str = "NETWORKFUZZER",
    called_ae: str = "ANY-SCP",
    enum_ae: bool = False,
    map_capabilities: bool = False,
    timeout: float = 5.0,
) -> str:
    """Discover and fingerprint a DICOM service.

    Sends a C-ECHO probe to test reachability, extracts the implementation
    class UID and version name from A-ASSOCIATE-AC to identify the product
    (Orthanc, DCMTK, dcm4che, GE, Siemens, Philips, etc.) and version.

    Optionally enumerates accepted AE titles (enum_ae=True) using a built-in
    wordlist — reveals misconfigured AE title policies.

    Optionally maps supported SOP classes (map_capabilities=True) — determines
    whether the server exposes C-FIND, C-STORE, C-MOVE, C-GET.

    Always run this FIRST before scanning or fuzzing an unknown target.

    Args:
        host: Target server hostname or IP address.
        port: Target DICOM port (default 4242; common: 104, 4242, 11112).
        calling_ae: Calling AE title used by the probe (default NETWORKFUZZER).
        called_ae: Called AE title to try on the target (default ANY-SCP).
        enum_ae: Enumerate accepted AE titles using a wordlist (takes ~30s extra).
        map_capabilities: Probe which SOP classes are supported (takes ~60s extra).
        timeout: Per-operation timeout in seconds.

    Returns:
        JSON with probe result, fingerprint, and optionally AE enum + capability map.
    """
    result = runner.run_discovery(
        host=host,
        port=port,
        calling_ae=calling_ae,
        called_ae=called_ae,
        enum_ae=enum_ae,
        map_capabilities=map_capabilities,
        timeout=timeout,
    )
    return result.summary()


@mcp.tool()
def networkfuzzer_scan(
    host: str,
    port: int = 4242,
    calling_ae: str = "NETWORKFUZZER",
    called_ae: str = "ANY-SCP",
    checks: str = "all",
    timeout: float = 5.0,
) -> str:
    """Run structured DICOM vulnerability checks against a server.

    Executes deterministic checks for known vulnerability classes:

    - auth:  AE title validation — no-auth, wildcard AE ('', '*'), default AE titles
    - cfind: Unauthenticated C-FIND — patient enumeration (CRITICAL/HIPAA), study enumeration
    - dos:   Denial-of-service — max_pdu integer overflow (CVE-2024-28130 class),
             rapid association exhaustion
    - info:  Information disclosure — version/product disclosure, no-TLS encryption,
             verbose error messages

    Returns findings with severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), CVSS score,
    evidence, CVE reference, and remediation guidance.

    Args:
        host: Target server hostname or IP address.
        port: Target DICOM port.
        calling_ae: Calling AE title used by the checks.
        called_ae: Called AE title (use one discovered by networkfuzzer_discover).
        checks: Comma-separated categories or 'all'. Options: auth, cfind, dos, info.
        timeout: Per-check timeout in seconds.

    Returns:
        JSON with all findings, severity counts, and pass/fail per check.
    """
    result = runner.run_vuln_scan(
        host=host,
        port=port,
        calling_ae=calling_ae,
        called_ae=called_ae,
        checks=checks,
        timeout=timeout,
    )
    return result.summary()


@mcp.tool()
def networkfuzzer_report(
    host: str,
    port: int = 4242,
    findings_json: Optional[str] = None,
    discovery_json: Optional[str] = None,
    output_dir: str = "/tmp/nf_reports",
    formats: str = "html,json",
) -> str:
    """Generate an HTML and/or JSON security report from scan findings.

    Combines discovery and vulnerability scan results into a professional
    security report with severity breakdown, CVSS scores, remediation steps,
    capability tables, and accepted AE title listing.

    Args:
        host: Target host (used in report header).
        port: Target port (used in report header).
        findings_json: Path to JSON file from networkfuzzer_scan output.
                       If omitted, generates an empty template report.
        discovery_json: Path to JSON file from networkfuzzer_discover output (optional).
        output_dir: Directory where report files will be written.
        formats: Comma-separated formats: 'html', 'json' (default: both).

    Returns:
        Paths to the generated report files.
    """
    result = runner.run_report(
        host=host,
        port=port,
        findings_json=findings_json,
        discovery_json=discovery_json,
        output_dir=output_dir,
        formats=formats,
    )
    return result.summary()


# ---------------------------------------------------------------------------
# Fuzzing tools
# ---------------------------------------------------------------------------

@mcp.tool()
def networkfuzzer_fuzz(
    host: str,
    port: int = 4242,
    protocol: str = "dicom",
    fuzz_mode: str = "hybrid",
    timesteps: int = 10000,
    algorithm: str = "DQN",
    called_ae: str = "ORTHANC",
    calling_ae: str = "NETWORKFUZZER",
    test: bool = False,
    n_test: int = 10,
    exploration_rate: float = 0.15,
    output_dir: Optional[str] = None,
    seed_dir: Optional[str] = None,
) -> str:
    """Run RL-guided protocol fuzzing against a live DICOM server.

    Uses reinforcement learning (DQN or PPO) to learn which packet mutations
    trigger deeper code paths, crashes, or anomalous responses. The agent
    adapts based on server responses — more effective than random mutation.

    Fuzzing modes:
    - semantic:   Protocol-aware mutations (valid DICOM structure, boundary values)
    - aggressive: Payload injection (format strings, overflow, path traversal)
    - state:      Protocol state machine attacks (out-of-order PDUs, invalid sequences)
    - hybrid:     All combined — 187 attack combinations (recommended)

    Requires a running target server. Use networkfuzzer_discover first to get
    the correct called_ae for the target.

    Args:
        host: Target server hostname or IP address.
        port: Target DICOM port.
        protocol: Protocol adapter to use (currently: 'dicom').
        fuzz_mode: Fuzzing mode: semantic, aggressive, state, hybrid.
        timesteps: RL training steps. More = deeper exploration. Start with 5000 for quick test.
        algorithm: RL algorithm: 'DQN' (default) or 'PPO'.
        called_ae: Target server AE title (from discovery).
        calling_ae: Fuzzer's AE title.
        test: Run test episodes after training to evaluate the learned policy.
        n_test: Number of test episodes (when test=True).
        exploration_rate: Novel combination exploration rate (0.0-1.0).
        output_dir: Output directory for generated PCAPs.
        seed_dir: Optional directory with prior corpus .json files to seed field mutations.

    Returns:
        Training summary with coverage stats, crashes found, and PCAP paths.
    """
    result = runner.run_rl_fuzz(
        protocol=protocol,
        target_host=host,
        target_port=port,
        fuzz_mode=fuzz_mode,
        timesteps=timesteps,
        algorithm=algorithm,
        called_ae=called_ae,
        calling_ae=calling_ae,
        test=test,
        n_test=n_test,
        exploration_rate=exploration_rate,
        output_dir=output_dir,
        seed_dir=seed_dir,
    )
    return result.summary()


@mcp.tool()
def networkfuzzer_generate(
    mode: str = "attack",
    attack_type: Optional[str] = None,
    samples: int = 1000,
    epochs: int = 100,
    target_host: Optional[str] = None,
    target_port: int = 4242,
    pcap_output: Optional[str] = None,
) -> str:
    """Generate synthetic malicious DICOM traffic using GAN or Transformer models.

    Generates PCAP files without needing a live target server. Useful for
    creating attack traffic for testing detection systems or replay.

    Modes:
    - attack:      Use a predefined attack profile (use networkfuzzer_list to see profiles).
                   Examples: abort_injection, cve_payloads, ae_manipulation, dos_flood.
    - smart:       Feedback-guided generation using a trained GAN.
    - byte_model:  Byte-level Transformer generation (requires trained model checkpoint).

    Args:
        mode: Generation mode: attack, smart, or byte_model.
        attack_type: Attack profile name for 'attack' mode (see networkfuzzer_list).
        samples: Number of synthetic samples to generate.
        epochs: GAN training epochs.
        target_host: Target server for feedback scoring (smart mode only).
        target_port: Target port (smart mode only).
        pcap_output: Output directory for generated PCAPs.

    Returns:
        Paths to generated PCAP files and generation statistics.
    """
    result = runner.run_gan_generate(
        mode=mode,
        attack_type=attack_type,
        samples=samples,
        epochs=epochs,
        target_host=target_host,
        target_port=target_port,
        pcap_output=pcap_output,
    )
    return result.summary()


@mcp.tool()
def networkfuzzer_replay(
    pcap_file: Optional[str] = None,
    config_file: Optional[str] = None,
    interface: Optional[str] = None,
    extra_params: Optional[dict] = None,
) -> str:
    """Replay and mutate PCAP traffic against a target server.

    Replays captured or generated PCAP files while applying compiled fuzzing
    rules (.so plugins) to match and modify packets in flight. Can operate
    offline (PCAP file) or online (live network interface).

    Args:
        pcap_file: Path to PCAP file for offline replay. Required unless interface is set.
        config_file: Path to networkfuzzer.conf configuration file.
        interface: Network interface for live capture (requires root). Alternative to pcap_file.
        extra_params: Extra config parameters as key=value dict, passed via -X flags.
                      Example: {"forward.host": "localhost", "forward.port": "4242"}

    Returns:
        Replay statistics and paths to output PCAPs.
    """
    result = runner.run_replay(
        pcap_file=pcap_file,
        config_file=config_file,
        interface=interface,
        extra_params=extra_params,
    )
    return result.summary()


@mcp.tool()
def networkfuzzer_compile(
    input_xml: str,
    output_so: Optional[str] = None,
) -> str:
    """Compile an XML fuzzing rule into a .so shared library plugin.

    XML rules define packet matching conditions and modification callbacks.
    The compiled .so plugin is loaded by networkfuzzer_replay to match and
    modify packets in real time.

    Rule structure:
      <property type_property="FORWARD" if_satisfied="callback_fn">
        <event boolean_expression="(dicom.pdu_type == 1)"/>
      </property>

    Args:
        input_xml: Path to the XML rule file to compile.
        output_so: Output path for the compiled plugin. Defaults to input path with .so extension.

    Returns:
        Compilation result and path to the compiled .so plugin.
    """
    result = runner.run_compile(
        input_xml=input_xml,
        output_so=output_so,
    )
    return result.summary()


@mcp.tool()
def networkfuzzer_list(category: str = "protocols") -> str:
    """List available NetworkFuzzer capabilities.

    Args:
        category: What to list:
            'protocols'       — available protocol adapters (e.g. dicom)
            'attack_profiles' — GAN attack profiles (e.g. abort_injection, cve_payloads)
            'fuzz_modes'      — RL fuzzing modes (semantic, aggressive, state, hybrid)

    Returns:
        List of available items for the requested category.
    """
    category = category.lower().strip()
    if category == "protocols":
        items = runner.list_protocols()
        label = "Available protocols"
    elif category == "attack_profiles":
        items = runner.list_attack_profiles()
        label = "Available attack profiles"
    elif category == "fuzz_modes":
        items = runner.list_fuzz_modes()
        label = "Available fuzzing modes"
    else:
        return f"Unknown category '{category}'. Use: protocols, attack_profiles, fuzz_modes."

    if not items:
        return f"No {category} found (check installation)."
    return f"{label}:\n" + "\n".join(f"  - {item}" for item in items)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    """Entry point for the networkfuzzer-mcp console script."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
