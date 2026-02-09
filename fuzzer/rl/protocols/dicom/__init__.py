"""
DICOM Protocol Adapter for RL Fuzzing.

Provides DICOM-specific:
- Message structure (PDUs, DIMSE commands)
- Field semantics (Message ID, Context ID, etc.)
- State machine (Association, PDATA, Release)
- Response parsing
"""

from .adapter import DicomAdapter

__all__ = ['DicomAdapter']
