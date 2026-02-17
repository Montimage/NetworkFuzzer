#!/usr/bin/env python3
"""
Server Feedback Loop for Smart GAN Pipeline.

Wraps the existing RewardComputer and ServerMonitor to score session plans
by sending their PDUs to a live target and measuring depth/response.

Usage:
    scorer = FeedbackScorer("192.168.1.100", 4242)
    scored_plans = scorer.score_batch(plans)
    generator.update_with_scores(scored_plans)
"""

import time
import socket
import logging
from typing import List, Optional

from fuzzer.rl.reward import RewardComputer
from fuzzer.rl.server_monitor import ServerMonitor
from fuzzer.gan.session_planner import SessionPlan
from fuzzer.gan.semantic_pcap_builder import build_session_from_plan

logger = logging.getLogger(__name__)


class FeedbackScorer:
    """
    Scores session plans by sending PDUs to a live DICOM server.

    Uses RewardComputer._live_reward() for per-PDU depth scoring
    and ServerMonitor for health checks between batches.
    """

    def __init__(self, target_host, target_port=4242, called_ae="ORTHANC",
                 send_delay=0.1, health_check_interval=50):
        self.target_host = target_host
        self.target_port = target_port
        self.called_ae = called_ae
        self.send_delay = send_delay
        self.health_check_interval = health_check_interval

        # Server monitor for health checks
        self.monitor = ServerMonitor(
            target_host, target_port, called_ae=called_ae)

        # Reward computer for depth scoring
        self.reward_computer = RewardComputer(
            target_host=target_host,
            target_port=target_port,
            called_ae=called_ae,
            server_monitor=self.monitor,
        )

        # Scoring history
        self.scored_history: List[SessionPlan] = []

    def score_plan(self, plan):
        """
        Score a single session plan by sending its PDUs to the target.

        Builds PDUs from the plan, sends them as a TCP session, and
        captures the server's response to compute depth and score.

        Returns:
            SessionPlan with score, depth, and response_type filled in
        """
        try:
            pdu_list = build_session_from_plan(plan)
            if not pdu_list:
                plan.score = 0.0
                plan.depth = 0.0
                plan.response_type = "empty"
                return plan

            # Send PDUs as a session and score the interaction
            score, depth, response_type = self._send_and_score(pdu_list)
            plan.score = score
            plan.depth = depth
            plan.response_type = response_type

        except Exception as e:
            logger.debug(f"Error scoring plan: {e}")
            plan.score = 0.0
            plan.depth = 0.0
            plan.response_type = f"error:{e}"

        self.scored_history.append(plan)
        return plan

    def score_batch(self, plans, parallel=1):
        """
        Score a batch of plans with rate limiting and health checks.

        Args:
            plans: list of SessionPlan to score
            parallel: unused (reserved for future concurrent scoring)

        Returns:
            list of scored SessionPlan
        """
        scored = []
        for i, plan in enumerate(plans):
            # Health check every N requests
            if i > 0 and i % self.health_check_interval == 0:
                if not self.check_server_health():
                    logger.warning(
                        f"Server unhealthy at plan {i}/{len(plans)}, "
                        f"pausing 5s...")
                    time.sleep(5.0)
                    if not self.check_server_health():
                        logger.error("Server still unhealthy, stopping batch")
                        break

            scored_plan = self.score_plan(plan)
            scored.append(scored_plan)

            # Rate limiting
            if self.send_delay > 0:
                time.sleep(self.send_delay)

            # Progress log
            if (i + 1) % 20 == 0:
                avg_score = sum(p.score for p in scored) / len(scored)
                avg_depth = sum(p.depth for p in scored) / len(scored)
                logger.info(
                    f"Scored {i+1}/{len(plans)} plans | "
                    f"avg_score={avg_score:.1f} avg_depth={avg_depth:.1f}")

        return scored

    def _send_and_score(self, pdu_list):
        """
        Send PDUs to the server and compute score/depth from response.

        Concatenates all PDUs and sends them in a single TCP connection.
        The first server response determines the depth score.

        Returns:
            (score, depth, response_type)
        """
        score = 0.0
        depth = 0.0
        response_type = "none"

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(5.0)
            sock.connect((self.target_host, self.target_port))

            for pdu in pdu_list:
                try:
                    sock.sendall(pdu)
                except (BrokenPipeError, ConnectionResetError):
                    break

                try:
                    sock.settimeout(2.0)
                    resp = sock.recv(4096)

                    if not resp:
                        response_type = "closed"
                        score += 1.0
                        depth = max(depth, 0.5)
                        continue

                    resp_byte = resp[0]
                    if resp_byte == 0x02:  # ASSOC-AC
                        response_type = "accept"
                        score += 20.0
                        depth = max(depth, 4.0)
                    elif resp_byte == 0x03:  # ASSOC-RJ
                        response_type = "reject"
                        # Parse rejection source for depth
                        if len(resp) >= 10:
                            source = resp[8]
                            depth = max(depth, {1: 1.0, 2: 2.0, 3: 3.0}.get(source, 1.0))
                        score += 4.0 + depth * 2.0
                    elif resp_byte == 0x04:  # P-DATA response
                        response_type = "pdata_response"
                        score += 25.0
                        depth = max(depth, 5.0)
                    elif resp_byte == 0x06:  # RELEASE-RP
                        response_type = "release_rp"
                        score += 8.0
                        depth = max(depth, 3.0)
                    elif resp_byte == 0x07:  # ABORT
                        response_type = "abort"
                        score += 12.0
                        depth = max(depth, 3.0)
                    else:
                        response_type = f"type_0x{resp_byte:02x}"
                        score += 15.0
                        depth = max(depth, 2.0)

                except socket.timeout:
                    response_type = "timeout"
                    score += 8.0
                    depth = max(depth, 2.0)
                except ConnectionResetError:
                    response_type = "reset"
                    score += 0.5
                    depth = max(depth, 0.5)
                    break

            sock.close()

        except ConnectionRefusedError:
            response_type = "refused"
            score = 3.0
            # Check for crash
            time.sleep(0.3)
            try:
                check = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                check.settimeout(2.0)
                check.connect((self.target_host, self.target_port))
                check.close()
            except Exception:
                response_type = "crash"
                score = 100.0
                depth = 10.0

        except ConnectionResetError:
            response_type = "reset"
            score = 0.5
            depth = 0.5

        except socket.timeout:
            response_type = "connect_timeout"
            score = 8.0
            depth = 2.0

        except Exception as e:
            response_type = f"error:{e}"
            score = 1.0
            depth = 0.0

        return score, depth, response_type

    def check_server_health(self):
        """Check if the server is healthy via ServerMonitor."""
        try:
            snap = self.monitor.check_health(full=False)
            health = snap.health_score()
            return health >= 40.0
        except Exception as e:
            logger.debug(f"Health check failed: {e}")
            return False

    def get_scored_history(self):
        """Return all scored plans for generator retraining."""
        return self.scored_history

    def get_summary(self):
        """Get scoring summary statistics."""
        if not self.scored_history:
            return {"total": 0}

        scores = [p.score for p in self.scored_history]
        depths = [p.depth for p in self.scored_history]
        responses = {}
        for p in self.scored_history:
            responses[p.response_type] = responses.get(p.response_type, 0) + 1

        return {
            "total": len(self.scored_history),
            "avg_score": sum(scores) / len(scores),
            "max_score": max(scores),
            "avg_depth": sum(depths) / len(depths),
            "max_depth": max(depths),
            "response_distribution": responses,
        }
