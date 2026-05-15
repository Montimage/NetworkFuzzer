"""
NGAP protocol adapter for RL fuzzing of open5GS AMF.

Uses libmmt_tmobile.so (mmt-dpi) for ASN.1 APER encode/decode.
Transport: SCTP, PPID=60, port=38412.
"""

from .adapter import NgapAdapter

__all__ = ['NgapAdapter']
