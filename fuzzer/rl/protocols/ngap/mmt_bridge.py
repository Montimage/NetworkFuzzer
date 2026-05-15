#!/usr/bin/env python3
"""
ctypes bridge to libmmt_tmobile.so (mmt-dpi).

Exposes decode_ngap(), encode_ngap(), and get_nas_pdu() to Python.
The library must be loaded in dependency order:
  1. libmmt_core.so  (RTLD_GLOBAL so symbols are visible to the next load)
  2. libmmt_tmobile.so

Verified working with the installed libraries at:
  /opt/mmt/dpi/lib/libmmt_core.so
  /opt/mmt/dpi/lib/libmmt_tmobile.so

Symbols confirmed present (nm -D):
  decode_ngap, encode_ngap, get_nas_pdu, try_decode_ngap
"""

import ctypes
import logging
from typing import Optional

logger = logging.getLogger(__name__)

MMT_CORE_PATH    = '/opt/mmt/dpi/lib/libmmt_core.so'
MMT_MOBILE_PATH  = '/opt/mmt/dpi/lib/libmmt_tmobile.so'

# SCTP_SNDINFO ancillary data type constant (Linux kernel)
SCTP_SNDINFO = 2

# ── C struct mirrors ──────────────────────────────────────────────────────────

class _NasPdu(ctypes.Structure):
    """
    Mirror of the anonymous struct inside ngap_message_t:
        struct { const uint8_t *data; size_t size; } nas_pdu;
    """
    _fields_ = [
        ('data', ctypes.c_char_p),   # pointer into ASN.1 decoded memory
        ('size', ctypes.c_size_t),
    ]


class NgapMessage(ctypes.Structure):
    """
    Mirror of ngap_message_t from mmt-dpi/src/mmt_mobile/ngap/ngap.h:

        typedef struct ngap_message {
            uint16_t         procedure_code;
            NGAP_NGAP_PDU_PR pdu_present;   // enum → int
            uint64_t         ran_ue_id;
            uint64_t         amf_ue_id;
            struct { const uint8_t *data; size_t size; } nas_pdu;
        } ngap_message_t;

    pdu_present values (NGAP_NGAP_PDU_PR enum):
        1 = initiatingMessage
        2 = successfulOutcome
        3 = unsuccessfulOutcome
    """
    _fields_ = [
        ('procedure_code', ctypes.c_uint16),
        ('pdu_present',    ctypes.c_int),
        ('ran_ue_id',      ctypes.c_uint64),
        ('amf_ue_id',      ctypes.c_uint64),
        ('nas_pdu',        _NasPdu),
    ]


# ── Bridge singleton ──────────────────────────────────────────────────────────

class MmtNgapBridge:
    """
    Thin Python wrapper around the four NGAP functions exported by
    libmmt_tmobile.so.  One instance is shared across the adapter.
    """

    _instance: Optional['MmtNgapBridge'] = None

    def __new__(cls) -> 'MmtNgapBridge':
        # Singleton: load the shared library only once per process.
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._loaded = False
        return cls._instance

    def __init__(self):
        if self._loaded:
            return
        self._lib = self._load_library()
        self._bind_functions()
        self._loaded = True

    # ── Library loading ───────────────────────────────────────────────────

    @staticmethod
    def _load_library():
        # libmmt_core must be global so libmmt_tmobile can resolve its symbols.
        ctypes.CDLL(MMT_CORE_PATH, mode=ctypes.RTLD_GLOBAL)
        lib = ctypes.CDLL(MMT_MOBILE_PATH)
        logger.debug("Loaded %s", MMT_MOBILE_PATH)
        return lib

    def _bind_functions(self):
        lib = self._lib

        lib.try_decode_ngap.restype  = ctypes.c_bool
        lib.try_decode_ngap.argtypes = [ctypes.c_char_p, ctypes.c_uint32]

        lib.decode_ngap.restype  = ctypes.c_bool
        lib.decode_ngap.argtypes = [
            ctypes.POINTER(NgapMessage),
            ctypes.c_char_p,
            ctypes.c_uint32,
        ]

        lib.encode_ngap.restype  = ctypes.c_uint32
        lib.encode_ngap.argtypes = [
            ctypes.c_char_p,    # output buffer
            ctypes.c_uint32,    # buffer capacity
            ctypes.POINTER(NgapMessage),
            ctypes.c_char_p,    # original payload (template)
            ctypes.c_uint32,    # original payload length
        ]

        lib.get_nas_pdu.restype  = ctypes.c_uint32
        lib.get_nas_pdu.argtypes = [
            ctypes.c_char_p,    # output buffer
            ctypes.c_uint32,    # buffer capacity
            ctypes.c_char_p,    # NGAP payload
            ctypes.c_uint32,    # NGAP payload length
        ]

    # ── Public API ────────────────────────────────────────────────────────

    def can_decode(self, payload: bytes) -> bool:
        """Quick check: returns True if payload is valid APER-encoded NGAP."""
        return bool(self._lib.try_decode_ngap(payload, len(payload)))

    def decode(self, payload: bytes) -> Optional[NgapMessage]:
        """
        Decode NGAP APER bytes into an NgapMessage struct.
        Returns None if decoding fails (e.g. NGSetup which mmt-dpi doesn't handle).
        """
        msg = NgapMessage()
        ok  = self._lib.decode_ngap(ctypes.byref(msg), payload, len(payload))
        return msg if ok else None

    def encode(self, msg: NgapMessage, original_payload: bytes) -> Optional[bytes]:
        """
        Re-encode a (possibly mutated) NgapMessage back to APER bytes.
        original_payload is used as the structural template; only the
        fields present in NgapMessage are updated before re-encoding.
        Returns None if encoding fails.
        """
        buf = ctypes.create_string_buffer(4096)
        n   = self._lib.encode_ngap(
            buf, 4096,
            ctypes.byref(msg),
            original_payload, len(original_payload),
        )
        return bytes(buf[:n]) if n > 0 else None

    def get_nas_pdu(self, payload: bytes) -> bytes:
        """
        Extract the NAS-5G PDU blob from inside an NGAP payload.
        Returns empty bytes if no NAS PDU is present.
        """
        buf = ctypes.create_string_buffer(512)
        n   = self._lib.get_nas_pdu(buf, 512, payload, len(payload))
        return bytes(buf[:n]) if n > 0 else b''
