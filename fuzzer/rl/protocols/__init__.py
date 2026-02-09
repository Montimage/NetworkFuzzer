"""
Protocol-specific adapters for RL fuzzing.

Each protocol has its own submodule with an adapter implementation.
"""

# Import all protocol adapters to register them
from . import dicom

__all__ = ['dicom']
