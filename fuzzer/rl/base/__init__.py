"""
Base classes for protocol-agnostic RL fuzzing.

This module provides abstract interfaces that can be implemented
for any network protocol supported by mmt-dpi.
"""

from .protocol_adapter import ProtocolAdapter
from .generic_env import GenericFuzzEnv

__all__ = ['ProtocolAdapter', 'GenericFuzzEnv']
