"""Subprocess wrapper for NetworkFuzzer CLI commands.

Translates structured Python calls into CLI commands executed via subprocess.
No code-level coupling to existing modules — all interaction is through the CLI.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class RunResult:
    """Result of a NetworkFuzzer CLI invocation."""

    success: bool
    exit_code: int
    stdout: str
    stderr: str
    output_dir: Optional[str] = None
    duration_seconds: float = 0.0

    def summary(self) -> str:
        """Return a human-readable summary of the run."""
        status = "SUCCESS" if self.success else f"FAILED (exit code {self.exit_code})"
        lines = [f"Status: {status}", f"Duration: {self.duration_seconds:.1f}s"]
        if self.output_dir:
            lines.append(f"Output: {self.output_dir}")
        # Include last 30 lines of stdout for context
        stdout_lines = self.stdout.strip().splitlines()
        if stdout_lines:
            tail = stdout_lines[-30:]
            lines.append("--- Output (last 30 lines) ---")
            lines.extend(tail)
        if not self.success and self.stderr.strip():
            stderr_lines = self.stderr.strip().splitlines()[-15:]
            lines.append("--- Errors (last 15 lines) ---")
            lines.extend(stderr_lines)
        return "\n".join(lines)


class FuzzerRunner:
    """Runs NetworkFuzzer CLI commands as subprocesses."""

    def __init__(self, project_root: Optional[str] = None, python_bin: Optional[str] = None):
        if project_root:
            self.project_root = Path(project_root).resolve()
        else:
            # Auto-detect: this file is at fuzzer/agent/runner.py
            self.project_root = Path(__file__).resolve().parent.parent.parent

        self.python_bin = python_bin or os.environ.get("PYTHON", sys.executable)
        self.networkfuzzer_bin = str(self.project_root / "networkfuzzer")

    def _run(self, cmd: list[str], timeout: int = 600, env_extra: Optional[dict] = None) -> RunResult:
        """Execute a command and return structured result."""
        env = os.environ.copy()
        if env_extra:
            env.update(env_extra)

        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(self.project_root),
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
            )
            duration = time.monotonic() - start
            return RunResult(
                success=proc.returncode == 0,
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_seconds=round(duration, 2),
            )
        except subprocess.TimeoutExpired as e:
            duration = time.monotonic() - start
            return RunResult(
                success=False,
                exit_code=-1,
                stdout=e.stdout or "",
                stderr=f"Command timed out after {timeout}s",
                duration_seconds=round(duration, 2),
            )
        except FileNotFoundError as e:
            duration = time.monotonic() - start
            return RunResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=f"Command not found: {e}",
                duration_seconds=round(duration, 2),
            )

    def run_rl_fuzz(
        self,
        protocol: str = "dicom",
        target_host: str = "localhost",
        target_port: int = 4242,
        fuzz_mode: str = "hybrid",
        timesteps: int = 10000,
        algorithm: str = "DQN",
        called_ae: str = "ORTHANC",
        calling_ae: str = "FUZZER",
        test: bool = False,
        n_test: int = 10,
        exploration_rate: float = 0.15,
        output_dir: Optional[str] = None,
        seed_dir: Optional[str] = None,
        timeout: int = 1800,
    ) -> RunResult:
        """Run RL-guided protocol fuzzing via train_protocol.py."""
        cmd = [
            self.python_bin, "-m", "fuzzer.rl.train_protocol",
            "--protocol", protocol,
            "--target-host", target_host,
            "--target-port", str(target_port),
            "--mode", fuzz_mode,
            "--timesteps", str(timesteps),
            "--algorithm", algorithm,
            "--called-ae", called_ae,
            "--calling-ae", calling_ae,
            "--exploration-rate", str(exploration_rate),
        ]
        if test:
            cmd.append("--test")
            cmd.extend(["--n-test", str(n_test)])
        if output_dir:
            cmd.extend(["--output-dir", output_dir])
        if seed_dir:
            cmd.extend(["--seed-dir", seed_dir])

        result = self._run(cmd, timeout=timeout)
        result.output_dir = output_dir or "fuzzer/data/pcap_output/rl_generated"
        return result

    def run_gan_generate(
        self,
        mode: str = "attack",
        attack_type: Optional[str] = None,
        samples: int = 1000,
        epochs: int = 100,
        target_host: Optional[str] = None,
        target_port: int = 4242,
        pcap_output: Optional[str] = None,
        timeout: int = 600,
    ) -> RunResult:
        """Run GAN-based synthetic traffic generation."""
        cmd = [
            self.python_bin, "-m", "fuzzer.gan.gan",
            "--mode", mode,
            "--samples", str(samples),
            "--epochs", str(epochs),
        ]
        if attack_type:
            cmd.extend(["--attack-type", attack_type])
        if target_host:
            cmd.extend(["--target-host", target_host])
            cmd.extend(["--target-port", str(target_port)])
        if pcap_output:
            cmd.extend(["--pcap-output", pcap_output])

        result = self._run(cmd, timeout=timeout)
        result.output_dir = pcap_output
        return result

    def run_byte_model(
        self,
        model_path: str,
        strategy: str = "temperature",
        temperature: float = 1.5,
        samples: int = 100,
        output_dir: Optional[str] = None,
        timeout: int = 300,
    ) -> RunResult:
        """Run byte-level Transformer PDU generation."""
        cmd = [
            self.python_bin, "-m", "fuzzer.models.byte_model.generate",
            "--model", model_path,
            "--strategy", strategy,
            "--count", str(samples),
            "--temp", str(temperature),
            "--to-pcap",
        ]
        if output_dir:
            cmd.extend(["--output-dir", output_dir])

        result = self._run(cmd, timeout=timeout)
        result.output_dir = output_dir or "fuzzer/data/pcap_output/ml_generated"
        return result

    def run_replay(
        self,
        pcap_file: Optional[str] = None,
        config_file: Optional[str] = None,
        interface: Optional[str] = None,
        extra_params: Optional[dict] = None,
        timeout: int = 300,
    ) -> RunResult:
        """Replay/mutate PCAP traffic against a target."""
        cmd = [self.networkfuzzer_bin, "replay"]
        if pcap_file:
            cmd.extend(["-t", pcap_file])
        if config_file:
            cmd.extend(["-c", config_file])
        if interface:
            cmd.extend(["-i", interface])
        if extra_params:
            for key, value in extra_params.items():
                cmd.extend(["-X", f"{key}={value}"])

        return self._run(cmd, timeout=timeout)

    def run_compile(
        self,
        input_xml: str,
        output_so: Optional[str] = None,
        timeout: int = 60,
    ) -> RunResult:
        """Compile an XML rule to a .so plugin."""
        if output_so is None:
            output_so = str(Path(input_xml).with_suffix(".so"))

        cmd = [self.networkfuzzer_bin, "compile", output_so, input_xml]
        result = self._run(cmd, timeout=timeout)
        if result.success:
            result.output_dir = str(Path(output_so).parent)
        return result

    def list_protocols(self) -> list[str]:
        """List available protocol adapters."""
        result = self._run(
            [self.python_bin, "-m", "fuzzer.rl.train_protocol", "--list-protocols"],
            timeout=30,
        )
        if result.success:
            protocols = []
            for line in result.stdout.splitlines():
                line = line.strip()
                # Skip headers and separators
                if not line or line.startswith("-") or line.lower().startswith("available"):
                    continue
                # Extract protocol name (first word before spaces/parentheses)
                name = line.split()[0] if line.split() else None
                if name:
                    protocols.append(name)
            return protocols
        return []

    def list_attack_profiles(self) -> list[str]:
        """List available GAN attack profiles."""
        # Import-free approach: run a one-liner to print the keys
        cmd = [
            self.python_bin, "-c",
            "from fuzzer.gan.attack_profiles import ATTACK_PROFILES; "
            "print('\\n'.join(sorted(ATTACK_PROFILES.keys())))",
        ]
        result = self._run(cmd, timeout=15)
        if result.success:
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return []

    def list_fuzz_modes(self) -> list[str]:
        """List available RL fuzzing modes."""
        return ["semantic", "aggressive", "state", "hybrid"]

    # ------------------------------------------------------------------
    # Pentest operations
    # ------------------------------------------------------------------

    def run_discovery(
        self,
        host: str,
        port: int,
        calling_ae: str = "NETWORKFUZZER",
        called_ae: str = "ANY-SCP",
        enum_ae: bool = False,
        map_capabilities: bool = False,
        timeout: float = 5.0,
    ) -> RunResult:
        """Run DICOM service discovery (probe + optional AE enum + capability map)."""
        cmd = [
            self.python_bin, "-m", "fuzzer.pentest.discovery.dicom_probe",
            "--host", host,
            "--port", str(port),
            "--calling-ae", calling_ae,
            "--called-ae", called_ae,
            "--timeout", str(timeout),
        ]
        if enum_ae:
            cmd.append("--enum-ae")

        result = self._run(cmd, timeout=int(timeout * 30))

        # Optionally run capability mapping as a second pass
        if map_capabilities and result.success:
            cap_cmd = [
                self.python_bin, "-m", "fuzzer.pentest.discovery.capability_map",
                "--host", host,
                "--port", str(port),
                "--calling-ae", calling_ae,
                "--called-ae", called_ae,
                "--timeout", str(timeout),
            ]
            cap_result = self._run(cap_cmd, timeout=120)
            # Merge stdout
            result.stdout = (
                result.stdout.rstrip()
                + "\n\n--- Capability Map ---\n"
                + cap_result.stdout
            )

        return result

    def run_vuln_scan(
        self,
        host: str,
        port: int,
        calling_ae: str = "NETWORKFUZZER",
        called_ae: str = "ANY-SCP",
        checks: str = "all",
        timeout: float = 5.0,
    ) -> RunResult:
        """Run structured DICOM vulnerability checks."""
        cmd = [
            self.python_bin, "-m", "fuzzer.pentest.vulnscan.scanner",
            "--host", host,
            "--port", str(port),
            "--calling-ae", calling_ae,
            "--called-ae", called_ae,
            "--checks", checks,
            "--timeout", str(timeout),
        ]
        return self._run(cmd, timeout=300)

    def run_report(
        self,
        host: str,
        port: int,
        findings_json: Optional[str] = None,
        discovery_json: Optional[str] = None,
        output_dir: str = ".",
        formats: str = "html,json",
    ) -> RunResult:
        """Generate HTML/JSON security report from findings."""
        cmd = [
            self.python_bin, "-m", "fuzzer.pentest.reporting.generator",
            "--host", host,
            "--port", str(port),
            "--output-dir", output_dir,
            "--format", formats,
        ]
        if findings_json:
            cmd.extend(["--findings", findings_json])
        if discovery_json:
            cmd.extend(["--discovery", discovery_json])

        result = self._run(cmd, timeout=60)
        result.output_dir = output_dir
        return result
