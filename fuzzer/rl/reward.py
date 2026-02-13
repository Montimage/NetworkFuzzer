#!/usr/bin/env python3
"""
Reward computation for RL-guided DICOM fuzzing.

Computes reward signals from:
  1. mmt-security rule triggers on generated PCAPs
  2. Live target responses: PDU type, rejection reason, response time
  3. Novelty bonuses for new rule triggers and response types
  4. Server health degradation: before/after comparison via DICOM probes
  5. Critical field targeting bonuses (v2)

v2 Improvements:
  - Penalize common "graceful" responses (reset, common rejects)
  - Novelty decay for repeated response types
  - Aggressive response time scaling
  - Critical field mutation bonuses
  - Rare response type detection
"""

import os
import subprocess
import tempfile
import logging
import time
import struct
import select
import socket

from scapy.all import wrpcap

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# DICOM A-ASSOCIATE-RJ rejection sources and reasons
RJ_SOURCES = {1: "DUL-service-user", 2: "DUL-service-provider-ACSE", 3: "DUL-service-provider-presentation"}
RJ_REASONS_USER = {
    1: "no-reason", 2: "application-context-unsupported",
    3: "calling-AE-not-recognized", 7: "called-AE-not-recognized",
}
RJ_REASONS_ACSE = {1: "no-reason", 2: "protocol-version-not-supported"}
RJ_REASONS_PRES = {0: "no-reason", 1: "temporary-congestion", 2: "local-limit-exceeded"}

# Parser depth scores — deeper parsing = more interesting
RJ_SOURCE_DEPTH = {1: 1.0, 2: 2.0, 3: 3.0}

# v3: Response type base rewards (differentiated)
# De-prioritize silent closes and common rejections
# Promote true hangs, crashes, and deep parsing errors
RESPONSE_BASE_REWARDS = {
    "reset": 0.5,           # Very common, server just closes - not interesting
    "closed": 0.5,          # Connection closed normally - not interesting
    "silent_close": 1.0,    # Server closed without response - expected for malformed input
    "reject": 4.0,          # Server parsed and rejected - somewhat interesting
    "abort": 12.0,          # Server entered abort state - interesting!
    "true_hang": 50.0,      # TRUE hang: socket alive, no response - VERY interesting!
    "timeout": 8.0,         # Generic timeout (may be silent close) - low reward
    "accept": 20.0,         # Accepted despite mutations - interesting!
    "refused": 3.0,         # Connection refused
    "connect_timeout": 8.0, # Couldn't connect - may indicate DoS
}

# v2: Common rejection reasons to penalize (these are "normal" rejections)
COMMON_REJECT_REASONS = {
    ("DUL-service-user", "called-AE-not-recognized"),
    ("DUL-service-user", "calling-AE-not-recognized"),
    ("DUL-service-user", "no-reason"),
    ("DUL-service-provider-ACSE", "protocol-version-not-supported"),
}

# v2: Rare/interesting rejection reasons to reward
RARE_REJECT_REASONS = {
    ("DUL-service-provider-presentation", "temporary-congestion"),
    ("DUL-service-provider-presentation", "local-limit-exceeded"),
}

# v2: Critical DICOM field offsets for ASSOC_RQ PDU
# Mutations hitting these fields get bonus rewards
CRITICAL_FIELDS_ASSOC_RQ = {
    # PDU header
    (0, 1): ("pdu_type", 3.0),           # PDU type byte
    (2, 6): ("pdu_length", 5.0),         # PDU length (4 bytes) - very important!
    (6, 8): ("protocol_version", 2.0),   # Protocol version
    # AE titles
    (10, 26): ("called_ae", 2.0),        # Called AE title (16 bytes)
    (26, 42): ("calling_ae", 1.5),       # Calling AE title (16 bytes)
    # Variable items start at offset 74
    (74, 76): ("app_ctx_type", 2.5),     # Application context item type
    (76, 78): ("app_ctx_len", 4.0),      # Application context length
}

# v2: Critical DICOM field offsets for PDATA PDU
CRITICAL_FIELDS_PDATA = {
    (0, 1): ("pdu_type", 3.0),           # PDU type byte (should be 0x04)
    (2, 6): ("pdu_length", 5.0),         # PDU length
    (6, 10): ("pdv_length", 4.5),        # PDV item length
    (10, 11): ("context_id", 2.0),       # Presentation context ID
    (11, 12): ("msg_control", 3.0),      # Message control header
    # DIMSE command elements (implicit VR LE)
    (12, 16): ("cmd_group_len_tag", 2.0),
    (16, 20): ("cmd_group_len_val", 3.0),
}


def parse_reject_pdu(response):
    """Parse A-ASSOCIATE-RJ PDU to extract rejection details.

    A-ASSOCIATE-RJ format (10 bytes):
      byte 0: 0x03 (PDU type)
      byte 1: reserved
      bytes 2-5: PDU length (4)
      byte 6: reserved
      byte 7: result (1=rejected-permanent, 2=rejected-transient)
      byte 8: source (1=DUL-user, 2=ACSE, 3=presentation)
      byte 9: reason/diag
    """
    info = {"result": 0, "source": 0, "source_name": "unknown",
            "reason": 0, "reason_name": "unknown", "depth": 1.0}

    if len(response) < 10:
        return info

    info["result"] = response[7]
    info["source"] = response[8]
    info["reason"] = response[9]
    info["source_name"] = RJ_SOURCES.get(response[8], f"unknown-{response[8]}")
    info["depth"] = RJ_SOURCE_DEPTH.get(response[8], 1.0)

    if response[8] == 1:
        info["reason_name"] = RJ_REASONS_USER.get(response[9], f"code-{response[9]}")
    elif response[8] == 2:
        info["reason_name"] = RJ_REASONS_ACSE.get(response[9], f"code-{response[9]}")
    elif response[8] == 3:
        info["reason_name"] = RJ_REASONS_PRES.get(response[9], f"code-{response[9]}")

    return info


class RewardComputer:
    """
    Compute reward for a mutated DICOM PDU.

    Reward signals:
      - mmt-security rule triggers (novelty bonus for new rules)
      - Server response type and rejection depth
      - Response time (longer = server worked harder)
      - Novelty bonus for previously unseen response types
      - Server health degradation (before/after DICOM probes)
      - Critical field mutation bonuses (v2)

    v2 Changes:
      - Differentiated base rewards per response type
      - Novelty decay: seen responses get diminishing returns
      - Aggressive time scaling for slow responses
      - Penalty for common/expected rejection reasons
    """

    def __init__(self, target_host=None, target_port=4242, called_ae="ORTHANC",
                 mmt_sec_path="/opt/mmt/security/bin/mmt_security",
                 server_monitor=None, pdu_type="assoc_rq"):
        self.target_host = target_host
        self.target_port = target_port
        self.called_ae = called_ae
        self.mmt_sec_path = mmt_sec_path
        self.server_monitor = server_monitor
        self.pdu_type = pdu_type  # "assoc_rq" or "pdata"

        # Per-episode tracking
        self.triggered_rules = set()
        self.seen_responses = set()
        self.seen_response_times = []

        # v2: Global tracking for novelty decay across training
        self.global_response_counts = {}  # response_sig -> count
        self.total_episodes = 0

        self._mmt_available = self._check_mmt()

    def get_critical_fields(self):
        """Get critical field definitions based on PDU type."""
        if self.pdu_type == "pdata":
            return CRITICAL_FIELDS_PDATA
        return CRITICAL_FIELDS_ASSOC_RQ

    def compute_field_bonus(self, mutated_positions):
        """
        Compute bonus reward for mutations hitting critical DICOM fields.

        Args:
            mutated_positions: set of byte offsets that were mutated

        Returns:
            (bonus_reward, field_hits dict)
        """
        critical_fields = self.get_critical_fields()
        bonus = 0.0
        field_hits = {}

        for pos in mutated_positions:
            for (start, end), (field_name, field_bonus) in critical_fields.items():
                if start <= pos < end:
                    if field_name not in field_hits:
                        field_hits[field_name] = 0
                    field_hits[field_name] += 1
                    # Diminishing returns for multiple hits on same field
                    if field_hits[field_name] == 1:
                        bonus += field_bonus
                    else:
                        bonus += field_bonus * 0.2  # 20% for additional hits
                    break

        return bonus, field_hits

    def _check_mmt(self):
        """Check if mmt_security is available."""
        try:
            subprocess.run(
                [self.mmt_sec_path, "-h"],
                capture_output=True, timeout=5,
                cwd="/tmp",
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def reset_episode(self):
        """Reset per-episode state."""
        self.triggered_rules = set()
        self.seen_responses = set()
        self.seen_response_times = []
        self.total_episodes += 1

    def compute_reward(self, packets, pdu_bytes=None, mutated_positions=None):
        """
        Compute total reward for generated packets/PDU.

        Args:
            packets: Scapy packets for mmt-security analysis
            pdu_bytes: Raw PDU bytes for live target testing
            mutated_positions: Set of byte offsets that were mutated (for field bonus)

        Returns:
            (total_reward, info_dict)
        """
        reward = -1.0  # Step penalty
        info = {"step_penalty": -1, "mmt_alerts": 0, "new_rules": 0,
                "live_response": "none", "crash": False,
                "response_time_ms": 0, "reject_source": "", "reject_reason": "",
                "parser_depth": 0, "response_novelty": False,
                "health_before": -1, "health_after": -1, "health_delta": 0,
                "impact_score": 0, "echo_latency_delta_ms": 0,
                "connections_lost": 0, "echo_lost": False, "assoc_lost": False,
                "field_bonus": 0, "field_hits": {}}

        # 1. mmt-security offline analysis
        if self._mmt_available and packets:
            mmt_reward, mmt_info = self._mmt_reward(packets)
            reward += mmt_reward
            info["mmt_alerts"] = mmt_info["alerts"]
            info["new_rules"] = mmt_info["new_rules"]

        # 2. Live target testing with health monitoring
        if self.target_host and pdu_bytes:
            live_reward, live_info = self._live_reward_with_monitor(pdu_bytes)
            reward += live_reward
            info.update(live_info)

        # 3. v2: Critical field mutation bonus
        if mutated_positions:
            field_bonus, field_hits = self.compute_field_bonus(mutated_positions)
            reward += field_bonus
            info["field_bonus"] = round(field_bonus, 1)
            info["field_hits"] = field_hits

        return reward, info

    def _mmt_reward(self, packets):
        """Run mmt_security on a temp PCAP and parse alerts."""
        info = {"alerts": 0, "new_rules": 0}
        reward = 0.0

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            tmp_pcap = f.name

        try:
            wrpcap(tmp_pcap, packets)
            result = subprocess.run(
                [self.mmt_sec_path, "-t", tmp_pcap],
                capture_output=True, text=True, timeout=30,
                cwd="/tmp",
            )
            output = result.stdout + result.stderr

            alert_count = 0
            for line in output.splitlines():
                line_s = line.strip()
                if "alerts generated" in line_s:
                    parts = line_s.split()
                    if parts and parts[0].isdigit():
                        alert_count = int(parts[0])
                if "satisfied" in line_s.lower() or "detected" in line_s.lower() or "alert" in line_s.lower():
                    for token in line_s.split(","):
                        token = token.strip()
                        if token.isdigit():
                            rule_id = int(token)
                            if rule_id not in self.triggered_rules:
                                self.triggered_rules.add(rule_id)
                                info["new_rules"] += 1
                                reward += 10.0

            info["alerts"] = alert_count
            if alert_count > 0 and info["new_rules"] == 0:
                reward += 2.0

        except subprocess.TimeoutExpired:
            reward += 5.0
        except Exception as e:
            logger.debug(f"mmt_sec error: {e}")
        finally:
            try:
                os.unlink(tmp_pcap)
            except OSError:
                pass

        return reward, info

    def _live_reward_with_monitor(self, pdu_bytes, do_health_check=True):
        """
        Send PDU to live target with before/after health monitoring.

        v2: Health checks are now optional and controlled by caller.
        """
        # v2: Only do health check if requested (caller controls frequency)
        health_before = None
        if self.server_monitor and do_health_check:
            try:
                health_before = self.server_monitor.check_health(full=False)
            except Exception as e:
                logger.debug(f"Pre-fuzz health check failed: {e}")

        # Send the fuzzed PDU
        live_reward, live_info = self._live_reward(pdu_bytes)

        # Take post-fuzz health snapshot
        if self.server_monitor and health_before and do_health_check:
            try:
                # v2: Reduced pause from 0.2 to 0.1
                time.sleep(0.1)
                health_after = self.server_monitor.check_health(full=False)
                degradation = self.server_monitor.compute_degradation(
                    health_before, health_after)

                live_info["health_before"] = degradation["health_before"]
                live_info["health_after"] = degradation["health_after"]
                live_info["health_delta"] = degradation["health_delta"]
                live_info["impact_score"] = degradation["impact_score"]
                live_info["echo_latency_delta_ms"] = degradation["echo_latency_delta_ms"]
                live_info["connections_lost"] = degradation["connections_lost"]
                live_info["echo_lost"] = degradation["echo_lost"]
                live_info["assoc_lost"] = degradation["assoc_lost"]

                # Reward from health degradation
                impact = degradation["impact_score"]
                if impact > 50:
                    live_reward += 30.0  # Severe degradation
                elif impact > 20:
                    live_reward += 15.0  # Moderate degradation
                elif impact > 5:
                    live_reward += 5.0   # Mild degradation

                # Extra reward for specific impacts
                if degradation["echo_lost"]:
                    live_reward += 20.0  # C-ECHO broke
                if degradation["assoc_lost"]:
                    live_reward += 15.0  # Can't associate anymore
                if degradation["connections_lost"] > 0:
                    live_reward += degradation["connections_lost"] * 5.0

                # Echo latency increase reward
                echo_delta = degradation["echo_latency_delta_ms"]
                if echo_delta > 500:
                    live_reward += 15.0
                elif echo_delta > 100:
                    live_reward += 8.0
                elif echo_delta > 20:
                    live_reward += 3.0

            except Exception as e:
                logger.debug(f"Post-fuzz health check failed: {e}")

        return live_reward, live_info

    def _live_reward(self, pdu_bytes):
        """
        Send PDU to live target with response timing and deep parsing.

        v3 Changes:
          - Distinguish true hangs from silent closes using socket state detection
          - Downgrade silent close rewards (expected behavior for malformed input)
          - Keep high rewards for true hangs and crashes
          - Use fine-grained polling to detect closures quickly
        """
        info = {"live_response": "none", "crash": False,
                "response_time_ms": 0, "reject_source": "", "reject_reason": "",
                "parser_depth": 0, "response_novelty": False,
                "common_response": False, "rare_response": False,
                "true_hang": False, "silent_close": False}
        reward = 0.0

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)

            t_connect = time.monotonic()
            sock.connect((self.target_host, self.target_port))
            sock.sendall(pdu_bytes)

            # v3: Use fine-grained polling to detect closures vs true hangs
            t_send = time.monotonic()
            response, closed, elapsed = wait_for_response_or_closure(sock, 3000)  # 3s timeout
            info["response_time_ms"] = round(elapsed, 1)

            self.seen_response_times.append(elapsed)

            if closed:
                # Server closed connection without sending response
                info["live_response"] = "silent_close"
                info["silent_close"] = True
                info["parser_depth"] = 0.5
                reward += RESPONSE_BASE_REWARDS.get("silent_close", 1.0)
            
            elif not response:
                # No response but socket still alive - check if true hang
                if is_socket_alive(sock):
                    # TRUE HANG: socket alive but no response
                    info["live_response"] = "true_hang"
                    info["true_hang"] = True
                    info["parser_depth"] = 5.0
                    reward += RESPONSE_BASE_REWARDS.get("true_hang", 50.0)
                else:
                    # Socket died during wait
                    info["live_response"] = "closed"
                    info["parser_depth"] = 0.5
                    reward += RESPONSE_BASE_REWARDS.get("closed", 0.5)

            elif response and len(response) >= 1:
                resp_type = response[0]

                if resp_type == 0x03:  # A-ASSOCIATE-RJ
                    info["live_response"] = "reject"
                    rj = parse_reject_pdu(response)
                    info["reject_source"] = rj["source_name"]
                    info["reject_reason"] = rj["reason_name"]
                    info["parser_depth"] = rj["depth"]

                    # v2: Base reward from lookup
                    reward += RESPONSE_BASE_REWARDS.get("reject", 4.0)
                    # Depth bonus (deeper parsing = more interesting)
                    reward += rj["depth"] * 2.0

                    # v2: Penalize common rejection reasons
                    reject_key = (rj["source_name"], rj["reason_name"])
                    if reject_key in COMMON_REJECT_REASONS:
                        reward -= 2.0  # Penalty for common rejection
                        info["common_response"] = True
                    elif reject_key in RARE_REJECT_REASONS:
                        reward += 8.0  # Bonus for rare rejection
                        info["rare_response"] = True

                elif resp_type == 0x07:  # A-ABORT
                    info["live_response"] = "abort"
                    info["parser_depth"] = 3.0
                    if len(response) >= 10:
                        info["reject_source"] = f"abort-source-{response[8]}"
                        info["reject_reason"] = f"abort-reason-{response[9]}"
                    reward += RESPONSE_BASE_REWARDS.get("abort", 12.0)

                elif resp_type == 0x02:  # A-ASSOCIATE-AC
                    info["live_response"] = "accept"
                    info["parser_depth"] = 4.0
                    reward += RESPONSE_BASE_REWARDS.get("accept", 20.0)

                else:
                    # Unknown response type - very interesting!
                    info["live_response"] = f"type_0x{resp_type:02x}"
                    info["parser_depth"] = 2.0
                    reward += 15.0  # Unknown types are interesting
                    info["rare_response"] = True

            # v3: Time bonus only for responses, not for silent closes
            if response and not closed:
                # Longer response = server worked harder = more interesting
                time_bonus = min(elapsed / 8.0, 25.0)
                reward += time_bonus
                info["time_bonus"] = round(time_bonus, 1)
            elif info.get("true_hang"):
                # True hangs get extra time bonus
                time_bonus = min(elapsed / 4.0, 40.0)
                reward += time_bonus
                info["time_bonus"] = round(time_bonus, 1)

            # v2: Novelty bonus with decay
            response_sig = (info["live_response"], info.get("reject_source", ""),
                            info.get("reject_reason", ""))

            # Track globally for decay
            self.global_response_counts[response_sig] = \
                self.global_response_counts.get(response_sig, 0) + 1
            count = self.global_response_counts[response_sig]

            if response_sig not in self.seen_responses:
                self.seen_responses.add(response_sig)
                info["response_novelty"] = True
                # First time in episode: full novelty bonus
                # But decay based on global count
                novelty_bonus = max(10.0 / (1 + count * 0.1), 2.0)
                reward += novelty_bonus
                info["novelty_bonus"] = round(novelty_bonus, 1)

        # Note: socket.timeout should not happen with wait_for_response_or_closure
        # but keep this as fallback
        except socket.timeout:
            t_timeout = time.monotonic()
            info["response_time_ms"] = round((t_timeout - t_send) * 1000.0, 1)
            
            # Check if socket is still alive
            if is_socket_alive(sock):
                info["live_response"] = "true_hang"
                info["true_hang"] = True
                info["parser_depth"] = 5.0
                reward += RESPONSE_BASE_REWARDS.get("true_hang", 50.0)
            else:
                info["live_response"] = "timeout"
                info["parser_depth"] = 2.0
                reward += RESPONSE_BASE_REWARDS.get("timeout", 8.0)

            # Verify crash
            try:
                check = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                check.settimeout(2.0)
                check.connect((self.target_host, self.target_port))
                check.close()
            except (ConnectionRefusedError, socket.timeout):
                info["crash"] = True
                reward += 80.0  # v3: High crash bonus

        except ConnectionResetError:
            info["live_response"] = "reset"
            info["silent_close"] = True
            info["parser_depth"] = 0.5
            # v3: Very low reward for reset - expected behavior for malformed input
            reward += RESPONSE_BASE_REWARDS.get("reset", 0.5)

        except ConnectionRefusedError:
            info["live_response"] = "refused"
            reward += RESPONSE_BASE_REWARDS.get("refused", 3.0)
            time.sleep(1.0)
            try:
                import socket as _sock
                check = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                check.settimeout(2.0)
                check.connect((self.target_host, self.target_port))
                check.close()
            except Exception:
                info["crash"] = True
                reward += 100.0  # v3: Maximum crash bonus
        except socket.timeout:
            info["live_response"] = "connect_timeout"
            reward += RESPONSE_BASE_REWARDS.get("connect_timeout", 8.0)
        except Exception as e:
            info["live_response"] = f"error:{e}"
            reward += 2.0
        finally:
            try:
                sock.close()
            except Exception:
                pass

        return reward, info
