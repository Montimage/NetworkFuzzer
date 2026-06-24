"""
Protocol-specific adapters for RL fuzzing.

Each protocol has its own submodule with an adapter implementation.
"""

# Import all protocol adapters to register them
from . import dicom
from . import ngap
from . import ngap_nas
from . import pfcp
from . import gtpu
from . import sbi
from . import ella_api

__all__ = ['dicom', 'ngap', 'ngap_nas', 'pfcp', 'gtpu', 'sbi', 'ella_api']
