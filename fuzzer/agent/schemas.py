"""Pydantic input schemas for NetworkFuzzer LangChain tools."""

from typing import Optional

from pydantic import BaseModel, Field


class RLFuzzInput(BaseModel):
    """Input schema for RL-guided protocol fuzzing."""

    protocol: str = Field(
        default="dicom",
        description="Protocol to fuzz (e.g. 'dicom'). Use list_capabilities to see available protocols.",
    )
    target_host: str = Field(
        default="localhost",
        description="Target server hostname or IP address.",
    )
    target_port: int = Field(
        default=4242,
        description="Target server port.",
    )
    fuzz_mode: str = Field(
        default="hybrid",
        description="Fuzzing mode: 'semantic' (protocol-aware mutations), 'aggressive' (payload injection), "
        "'state' (state machine attacks), or 'hybrid' (all combined).",
    )
    timesteps: int = Field(
        default=10000,
        description="Number of RL training timesteps. More steps = deeper exploration but longer runtime.",
    )
    algorithm: str = Field(
        default="DQN",
        description="RL algorithm: 'DQN' or 'PPO'.",
    )
    called_ae: str = Field(
        default="ORTHANC",
        description="DICOM Called AE title of the target server.",
    )
    calling_ae: str = Field(
        default="FUZZER",
        description="DICOM Calling AE title used by the fuzzer.",
    )
    test: bool = Field(
        default=False,
        description="Run test episodes after training to evaluate the learned policy.",
    )
    n_test: int = Field(
        default=10,
        description="Number of test episodes to run (only used when test=True).",
    )
    exploration_rate: float = Field(
        default=0.15,
        description="Novel combo exploration rate (0.0-1.0).",
    )
    output_dir: Optional[str] = Field(
        default=None,
        description="Output directory for generated PCAPs. Defaults to fuzzer/data/pcap_output/rl_generated.",
    )


class GANGenerateInput(BaseModel):
    """Input schema for GAN/byte-model traffic generation."""

    mode: str = Field(
        default="attack",
        description="Generation mode: 'flow' (flow-level), 'protocol' (protocol-level), "
        "'attack' (attack profile), 'smart' (feedback-guided), or 'byte_model' (Transformer-based).",
    )
    attack_type: Optional[str] = Field(
        default=None,
        description="Attack profile name for 'attack' mode (e.g. 'abort_injection', 'cve_payloads'). "
        "Use list_capabilities to see available profiles.",
    )
    samples: int = Field(
        default=1000,
        description="Number of synthetic samples to generate.",
    )
    epochs: int = Field(
        default=100,
        description="Training epochs for the GAN model.",
    )
    target_host: Optional[str] = Field(
        default=None,
        description="Target server host for feedback scoring (smart mode).",
    )
    target_port: int = Field(
        default=4242,
        description="Target server port (smart mode).",
    )
    pcap_output: Optional[str] = Field(
        default=None,
        description="Output directory for generated PCAPs.",
    )
    # Byte model specific
    strategy: str = Field(
        default="temperature",
        description="Byte model generation strategy: 'temperature', 'topk-error', 'prefix', or 'gradient'.",
    )
    temperature: float = Field(
        default=1.5,
        description="Sampling temperature for byte model (higher = more random).",
    )
    model_path: Optional[str] = Field(
        default=None,
        description="Path to trained byte model checkpoint (required for byte_model mode).",
    )


class ReplayInput(BaseModel):
    """Input schema for PCAP replay/mutation."""

    pcap_file: Optional[str] = Field(
        default=None,
        description="Path to PCAP file to replay (offline mode). Required unless interface is set.",
    )
    config_file: Optional[str] = Field(
        default=None,
        description="Path to networkfuzzer.conf configuration file.",
    )
    interface: Optional[str] = Field(
        default=None,
        description="Network interface for live capture (online mode). Requires root privileges.",
    )
    extra_params: Optional[dict] = Field(
        default=None,
        description="Extra config parameters as key=value pairs, passed via -X flags.",
    )


class CompileRuleInput(BaseModel):
    """Input schema for XML rule compilation."""

    input_xml: str = Field(
        description="Path to the XML rule file to compile.",
    )
    output_so: Optional[str] = Field(
        default=None,
        description="Path for the compiled .so plugin output. Defaults to input path with .so extension.",
    )


class ListCapabilitiesInput(BaseModel):
    """Input schema for listing NetworkFuzzer capabilities."""

    category: str = Field(
        default="protocols",
        description="What to list: 'protocols' (available protocol adapters), "
        "'attack_profiles' (GAN attack profiles), or 'fuzz_modes' (RL fuzzing modes).",
    )


class DiscoverInput(BaseModel):
    """Input schema for DICOM service discovery."""

    host: str = Field(description="Target server hostname or IP address.")
    port: int = Field(default=4242, description="Target DICOM port.")
    calling_ae: str = Field(default="NETWORKFUZZER", description="Calling AE title used by the probe.")
    called_ae: str = Field(default="ANY-SCP", description="Called AE title to try on the target.")
    enum_ae: bool = Field(
        default=False,
        description="Enumerate accepted AE titles using a built-in wordlist. "
        "Takes longer but reveals misconfigured AE title policies.",
    )
    map_capabilities: bool = Field(
        default=False,
        description="Probe which DICOM SOP classes (C-ECHO, C-FIND, C-STORE, C-MOVE) "
        "the server supports. Adds ~30s but provides richer findings.",
    )
    timeout: float = Field(default=5.0, description="Per-operation timeout in seconds.")


class VulnScanInput(BaseModel):
    """Input schema for DICOM vulnerability scanning."""

    host: str = Field(description="Target server hostname or IP address.")
    port: int = Field(default=4242, description="Target DICOM port.")
    calling_ae: str = Field(default="NETWORKFUZZER", description="Calling AE title used by checks.")
    called_ae: str = Field(default="ANY-SCP", description="Called AE title to use when connecting.")
    checks: str = Field(
        default="all",
        description="Comma-separated check categories to run. "
        "Options: 'auth' (AE title validation), 'cfind' (unauthenticated C-FIND), "
        "'dos' (denial-of-service), 'info' (information disclosure). "
        "Use 'all' to run every check.",
    )
    timeout: float = Field(default=5.0, description="Per-check timeout in seconds.")


class ReportInput(BaseModel):
    """Input schema for security report generation."""

    host: str = Field(description="Target host (for report header).")
    port: int = Field(default=4242, description="Target port (for report header).")
    findings_json: Optional[str] = Field(
        default=None,
        description="Path to a JSON file containing scan findings "
        "(output of run_vuln_scan saved to disk). "
        "If omitted, an empty findings section is generated.",
    )
    discovery_json: Optional[str] = Field(
        default=None,
        description="Path to a JSON file containing discovery results "
        "(output of run_discovery saved to disk). Optional.",
    )
    output_dir: str = Field(
        default=".",
        description="Directory where the report files will be written.",
    )
    formats: str = Field(
        default="html,json",
        description="Comma-separated report formats to generate: 'html', 'json'.",
    )
