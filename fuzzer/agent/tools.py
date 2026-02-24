"""LangChain tool definitions for NetworkFuzzer.

Provides 5 tools that wrap NetworkFuzzer CLI commands:
  1. fuzz_with_rl      — RL-guided protocol fuzzing
  2. generate_traffic  — GAN/byte-model synthetic traffic generation
  3. replay_traffic    — Replay/mutate PCAP against target
  4. compile_fuzz_rule — Compile XML rule to .so plugin
  5. list_capabilities — List protocols, attack profiles, fuzz modes
"""

from typing import Optional

from langchain_core.tools import StructuredTool

from fuzzer.agent.runner import FuzzerRunner
from fuzzer.agent.schemas import (
    CompileRuleInput,
    GANGenerateInput,
    ListCapabilitiesInput,
    ReplayInput,
    RLFuzzInput,
)


def _rl_fuzz(runner: FuzzerRunner, **kwargs) -> str:
    inp = RLFuzzInput(**kwargs)
    result = runner.run_rl_fuzz(
        protocol=inp.protocol,
        target_host=inp.target_host,
        target_port=inp.target_port,
        fuzz_mode=inp.fuzz_mode,
        timesteps=inp.timesteps,
        algorithm=inp.algorithm,
        called_ae=inp.called_ae,
        calling_ae=inp.calling_ae,
        test=inp.test,
        n_test=inp.n_test,
        exploration_rate=inp.exploration_rate,
        output_dir=inp.output_dir,
    )
    return result.summary()


def _generate_traffic(runner: FuzzerRunner, **kwargs) -> str:
    inp = GANGenerateInput(**kwargs)
    if inp.mode == "byte_model":
        if not inp.model_path:
            return "Error: model_path is required for byte_model mode."
        result = runner.run_byte_model(
            model_path=inp.model_path,
            strategy=inp.strategy,
            temperature=inp.temperature,
            samples=inp.samples,
            output_dir=inp.pcap_output,
        )
    else:
        result = runner.run_gan_generate(
            mode=inp.mode,
            attack_type=inp.attack_type,
            samples=inp.samples,
            epochs=inp.epochs,
            target_host=inp.target_host,
            target_port=inp.target_port,
            pcap_output=inp.pcap_output,
        )
    return result.summary()


def _replay_traffic(runner: FuzzerRunner, **kwargs) -> str:
    inp = ReplayInput(**kwargs)
    if not inp.pcap_file and not inp.interface:
        return "Error: either pcap_file (offline) or interface (online) must be specified."
    result = runner.run_replay(
        pcap_file=inp.pcap_file,
        config_file=inp.config_file,
        interface=inp.interface,
        extra_params=inp.extra_params,
    )
    return result.summary()


def _compile_rule(runner: FuzzerRunner, **kwargs) -> str:
    inp = CompileRuleInput(**kwargs)
    result = runner.run_compile(
        input_xml=inp.input_xml,
        output_so=inp.output_so,
    )
    return result.summary()


def _list_capabilities(runner: FuzzerRunner, **kwargs) -> str:
    inp = ListCapabilitiesInput(**kwargs)
    category = inp.category.lower()
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
        return f"Unknown category '{category}'. Use: protocols, attack_profiles, or fuzz_modes."

    if not items:
        return f"No {category} found (command may have failed — check installation)."
    return f"{label}:\n" + "\n".join(f"  - {item}" for item in items)


def create_networkfuzzer_tools(project_root: Optional[str] = None) -> list[StructuredTool]:
    """Create all NetworkFuzzer LangChain tools.

    Args:
        project_root: Path to NetworkFuzzer project root. Auto-detected if None.

    Returns:
        List of 5 StructuredTool instances ready for use with any LangChain agent.
    """
    runner = FuzzerRunner(project_root=project_root)

    return [
        StructuredTool.from_function(
            func=lambda **kw: _rl_fuzz(runner, **kw),
            name="fuzz_with_rl",
            description=(
                "Run RL-guided protocol fuzzing against a target server. "
                "Supports semantic (protocol-aware), aggressive (payload injection), "
                "state (state machine), and hybrid (all combined) fuzzing modes. "
                "Requires a running target server. Returns coverage stats, crashes found, "
                "and paths to generated PCAP files."
            ),
            args_schema=RLFuzzInput,
        ),
        StructuredTool.from_function(
            func=lambda **kw: _generate_traffic(runner, **kw),
            name="generate_traffic",
            description=(
                "Generate synthetic malicious network traffic using GAN or byte-level "
                "Transformer models. Modes: 'attack' (use predefined attack profiles), "
                "'smart' (feedback-guided generation), 'byte_model' (Transformer-based PDU "
                "generation). Returns paths to generated PCAP files."
            ),
            args_schema=GANGenerateInput,
        ),
        StructuredTool.from_function(
            func=lambda **kw: _replay_traffic(runner, **kw),
            name="replay_traffic",
            description=(
                "Replay and mutate PCAP traffic against a target. Can operate offline "
                "(from PCAP file) or online (live interface capture). Uses compiled "
                "fuzzing rules (.so plugins) to match and modify packets in flight."
            ),
            args_schema=ReplayInput,
        ),
        StructuredTool.from_function(
            func=lambda **kw: _compile_rule(runner, **kw),
            name="compile_fuzz_rule",
            description=(
                "Compile an XML fuzzing rule into a .so shared library plugin. "
                "The compiled plugin can then be loaded by the replay command to "
                "match and modify packets. Input is an XML rule file path."
            ),
            args_schema=CompileRuleInput,
        ),
        StructuredTool.from_function(
            func=lambda **kw: _list_capabilities(runner, **kw),
            name="list_capabilities",
            description=(
                "List available NetworkFuzzer capabilities. Categories: "
                "'protocols' (supported protocol adapters like DICOM), "
                "'attack_profiles' (GAN attack profiles like abort_injection, cve_payloads), "
                "'fuzz_modes' (RL fuzzing modes: semantic, aggressive, state, hybrid)."
            ),
            args_schema=ListCapabilitiesInput,
        ),
    ]
