#!/usr/bin/env python3
"""
Abstract Protocol Adapter Interface.

Implement this interface to add RL fuzzing support for any network protocol.
Each protocol adapter defines:
- Message structure and field semantics
- Valid/boundary mutation values
- Protocol state machine
- Response parsing
- Health check mechanism
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any, Callable
import struct


@dataclass
class FieldDefinition:
    """Definition of a protocol field that can be mutated."""
    name: str
    offset: Optional[int]  # Byte offset in message (None if variable)
    size: int              # Size in bytes
    encoding: str          # 'uint8', 'uint16_le', 'uint16_be', 'uint32_le', 'uint32_be', 'bytes', 'string'
    valid_values: List[Any] = field(default_factory=list)      # Known valid values
    boundary_values: List[Any] = field(default_factory=list)   # Edge case values
    description: str = ""


@dataclass
class StateTransition:
    """Definition of a protocol state transition."""
    name: str
    message_sequence: List[str]  # List of message type names
    description: str = ""
    is_valid: bool = True        # Whether this is a valid protocol sequence
    flood: bool = False          # Send intermediate PDUs without waiting for response


@dataclass
class PayloadTarget:
    """Definition of where payloads can be injected."""
    name: str
    field_name: str              # Which field to inject into
    max_size: Optional[int]      # Maximum size allowed (None = unlimited)
    encoding: str = "bytes"      # How to encode the payload
    preferred_sequence: Optional[str] = None  # State transition name that delivers this payload


@dataclass
class HealthCheckResult:
    """Result of a protocol health check."""
    is_healthy: bool
    latency_ms: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


class ProtocolAdapter(ABC):
    """
    Abstract base class for protocol-specific fuzzing logic.

    Implement this class to add support for a new protocol.
    See protocols/dicom/adapter.py for a complete example.
    """

    # Protocol identification
    @property
    @abstractmethod
    def protocol_name(self) -> str:
        """Return the protocol name (e.g., 'dicom', 'http2', 'sip')."""
        pass

    @property
    @abstractmethod
    def default_port(self) -> int:
        """Return the default port for this protocol."""
        pass

    # Field definitions
    @abstractmethod
    def get_semantic_fields(self) -> List[FieldDefinition]:
        """
        Return list of protocol fields that can be semantically mutated.

        These are fields where we know valid/boundary values.
        """
        pass

    @abstractmethod
    def get_mutation_values(self, field_name: str) -> List[Any]:
        """
        Return mutation values for a specific field.

        Should include both valid and boundary/invalid values.
        """
        pass

    # Message building
    @abstractmethod
    def build_message(self, message_type: str, fields: Dict[str, Any],
                      payloads: Dict[str, bytes]) -> bytes:
        """
        Build a protocol message with the specified field values and payloads.

        Args:
            message_type: Type of message to build (e.g., 'request', 'response')
            fields: Dictionary of field_name -> value
            payloads: Dictionary of target_name -> payload bytes

        Returns:
            The constructed message bytes
        """
        pass

    @abstractmethod
    def get_message_types(self) -> List[str]:
        """Return list of message types this protocol supports."""
        pass

    # State machine
    @abstractmethod
    def get_state_transitions(self) -> List[StateTransition]:
        """
        Return list of state transitions (message sequences) to test.

        Should include both valid sequences and invalid ones for fuzzing.
        """
        pass

    # Payload injection
    @abstractmethod
    def get_payload_targets(self) -> List[PayloadTarget]:
        """Return list of fields where payloads can be injected."""
        pass

    # Response parsing
    @abstractmethod
    def parse_response(self, data: bytes) -> Dict[str, Any]:
        """
        Parse a protocol response.

        Returns dict with at least:
        - 'type': response type name
        - 'success': bool indicating if response indicates success
        - 'error_code': optional error code
        """
        pass

    @abstractmethod
    def is_interesting_response(self, response: Dict[str, Any]) -> Tuple[bool, float]:
        """
        Determine if a response is interesting for fuzzing.

        Returns:
            (is_interesting, reward_multiplier)
        """
        pass

    # Health check
    @abstractmethod
    def check_health(self, host: str, port: int, timeout: float = 5.0) -> HealthCheckResult:
        """
        Check if the target server is healthy.

        This should send a simple request that a healthy server will respond to.
        """
        pass

    # Connection handling
    def get_connection_params(self) -> Dict[str, Any]:
        """
        Return connection parameters for this protocol.

        Override to customize socket options, SSL, etc.
        """
        return {
            'socket_type': 'tcp',  # 'tcp', 'udp', 'sctp'
            'use_ssl': False,
            'tcp_nodelay': True,
        }

    # Reward computation
    def compute_reward(self, response: Dict[str, Any], response_time_ms: float,
                       field_mutations: Dict[str, Any],
                       payload_injections: Dict[str, bytes]) -> float:
        """
        Compute reward for a fuzzing action.

        Override to customize reward computation for your protocol.
        Default implementation provides a reasonable baseline.
        """
        reward = 0.0

        # Base reward from response type
        is_interesting, multiplier = self.is_interesting_response(response)
        if is_interesting:
            reward += 10.0 * multiplier

        # Time bonus for slow responses
        if response_time_ms > 100:
            reward += 20.0
        elif response_time_ms > 50:
            reward += 10.0

        # Bonus for mutations that weren't rejected
        if response.get('success') and field_mutations:
            reward += 5.0 * len(field_mutations)

        return reward

    # Observation encoding
    def get_observation_size(self) -> int:
        """Return the size of the observation vector."""
        # Default: 6 fields + 5 response history + 4 counters + step = 16
        return 20

    def encode_observation(self, fields: Dict[str, Any],
                          response_history: List[str],
                          counters: Dict[str, int],
                          step: int, max_steps: int) -> List[float]:
        """
        Encode current state as observation vector.

        Override for protocol-specific encoding.
        """
        import numpy as np
        obs = np.zeros(self.get_observation_size(), dtype=np.float32)

        # Encode fields (first N slots)
        semantic_fields = self.get_semantic_fields()
        for i, field_def in enumerate(semantic_fields[:6]):
            if field_def.name in fields:
                val = fields[field_def.name]
                # Normalize based on encoding
                if field_def.encoding.startswith('uint'):
                    bits = int(field_def.encoding.replace('uint', '').replace('_le', '').replace('_be', ''))
                    max_val = (1 << bits) - 1
                    obs[i] = float(val) / max_val
                else:
                    obs[i] = 0.5  # Default for non-numeric

        # Response history (slots 6-10)
        for i, resp in enumerate(response_history[-5:]):
            obs[6 + i] = hash(resp) % 100 / 100.0

        # Counters (slots 11-14)
        obs[11] = min(counters.get('hangs', 0) / 10.0, 1.0)
        obs[12] = min(counters.get('crashes', 0) / 5.0, 1.0)
        obs[13] = min(counters.get('successes', 0) / 20.0, 1.0)
        obs[14] = step / max_steps

        return obs.tolist()


# Registry of protocol adapters
_PROTOCOL_REGISTRY: Dict[str, type] = {}


def register_protocol(name: str):
    """Decorator to register a protocol adapter."""
    def decorator(cls):
        _PROTOCOL_REGISTRY[name.lower()] = cls
        return cls
    return decorator


def get_protocol_adapter(name: str, **kwargs) -> ProtocolAdapter:
    """Get a protocol adapter by name."""
    name = name.lower()
    if name not in _PROTOCOL_REGISTRY:
        available = ', '.join(_PROTOCOL_REGISTRY.keys())
        raise ValueError(f"Unknown protocol: {name}. Available: {available}")
    return _PROTOCOL_REGISTRY[name](**kwargs)


def list_protocols() -> List[str]:
    """List all registered protocols."""
    return list(_PROTOCOL_REGISTRY.keys())
