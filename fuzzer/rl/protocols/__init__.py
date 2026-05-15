"""
Protocol-specific adapters for RL fuzzing.

Each protocol has its own submodule with an adapter implementation.
"""

# Import all protocol adapters to register them
from . import dicom
from . import ngap
from . import sbi

__all__ = ['dicom', 'ngap', 'sbi']
