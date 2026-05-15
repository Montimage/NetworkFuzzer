"""
HTTP/2 SBI protocol adapter for RL fuzzing of open5GS NFs.

Targets the 5G Service-Based Interface (3GPP TS 29.500) over plain TCP:
  NRF (TS 29.510)  — port 7777
  AMF (TS 29.518)  — port 7777
  SMF (TS 29.502)  — port 7779
  UDM, PCF, AUSF   — port 7777

Registered as 'sbi' with the protocol adapter registry.
"""

from .adapter import SbiAdapter

__all__ = ['SbiAdapter']
