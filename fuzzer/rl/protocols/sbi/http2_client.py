#!/usr/bin/env python3
"""
Minimal HTTP/2 frame builder and response parser for SBI fuzzing.

Builds raw HTTP/2 frames over a plain TCP socket without TLS.
Mirrors the approach in src/forward/proto/inject_http2.c:
  _http2_connect() sends client preface + SETTINGS;
  inject_http2_send_packet() sends raw frame bytes.

No external h2/hpack library required — uses literal HPACK encoding
(RFC 7541 §6.2.2) which is stateless and valid for connection-per-request
fuzzing where no dynamic table is ever established.

Attribute IDs mirror sdk/include/tcpip/http2.h:
  HTTP2_TYPE=1, HTTP2_HEADER_METHOD=2, HTTP2_HEADER_LENGTH=3,
  HTTP2_HEADER_STREAM_ID=4, HTTP2_PAYLOAD_STREAM_ID=5,
  HTTP2_PAYLOAD_LENGTH=6, HTTP2_PAYLOAD_DATA=7
"""

import struct
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# HTTP/2 constants  (mirrors http2.h from mmt-dpi SDK)
# ---------------------------------------------------------------------------

# Client connection preface (RFC 7540 §3.5)
H2_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'

# Frame type bytes (http2_header.type in http2.h)
FRAME_DATA          = 0x0
FRAME_HEADERS       = 0x1
FRAME_PRIORITY      = 0x2
FRAME_RST_STREAM    = 0x3
FRAME_SETTINGS      = 0x4
FRAME_PUSH_PROMISE  = 0x5
FRAME_PING          = 0x6
FRAME_GOAWAY        = 0x7
FRAME_WINDOW_UPDATE = 0x8
FRAME_CONTINUATION  = 0x9

# Frame flags
FLAG_END_STREAM  = 0x1
FLAG_END_HEADERS = 0x4
FLAG_ACK         = 0x1   # SETTINGS / PING

# SETTINGS parameter identifiers (RFC 7540 §6.5.2)
SETTINGS_HEADER_TABLE_SIZE      = 0x1
SETTINGS_ENABLE_PUSH            = 0x2
SETTINGS_MAX_CONCURRENT_STREAMS = 0x3
SETTINGS_INITIAL_WINDOW_SIZE    = 0x4
SETTINGS_MAX_FRAME_SIZE         = 0x5
SETTINGS_MAX_HEADER_LIST_SIZE   = 0x6

# GOAWAY / RST_STREAM error codes (RFC 7540 §7)
H2_NO_ERROR            = 0x0
H2_PROTOCOL_ERROR      = 0x1
H2_INTERNAL_ERROR      = 0x2
H2_FLOW_CONTROL_ERROR  = 0x3
H2_SETTINGS_TIMEOUT    = 0x4
H2_STREAM_CLOSED       = 0x5
H2_FRAME_SIZE_ERROR    = 0x6
H2_REFUSED_STREAM      = 0x7
H2_CANCEL              = 0x8
H2_COMPRESSION_ERROR   = 0x9
H2_CONNECT_ERROR       = 0xa
H2_ENHANCE_YOUR_CALM   = 0xb
H2_INADEQUATE_SECURITY = 0xc

# HPACK static table (RFC 7541 Appendix B) — entries relevant to SBI responses
_HPACK_STATIC: Dict[int, Tuple[str, str]] = {
    1:  (':authority',       ''),
    2:  (':method',          'GET'),
    3:  (':method',          'POST'),
    4:  (':path',            '/'),
    5:  (':path',            '/index.html'),
    6:  (':scheme',          'http'),
    7:  (':scheme',          'https'),
    8:  (':status',          '200'),
    9:  (':status',          '204'),
    10: (':status',          '206'),
    11: (':status',          '304'),
    12: (':status',          '400'),
    13: (':status',          '404'),
    14: (':status',          '500'),
    15: ('accept-charset',   ''),
    16: ('accept-encoding',  'gzip, deflate'),
    17: ('accept-language',  ''),
    18: ('accept-ranges',    ''),
    19: ('accept',           ''),
    20: ('access-control-allow-origin', ''),
    21: ('age',              ''),
    22: ('allow',            ''),
    23: ('authorization',    ''),
    24: ('cache-control',    ''),
    25: ('content-disposition', ''),
    26: ('content-encoding', ''),
    27: ('content-language', ''),
    28: ('content-length',   ''),
    29: ('content-location', ''),
    30: ('content-range',    ''),
    31: ('content-type',     ''),
    32: ('cookie',           ''),
    33: ('date',             ''),
    34: ('etag',             ''),
    35: ('expect',           ''),
    36: ('expires',          ''),
    37: ('from',             ''),
    38: ('host',             ''),
    39: ('if-match',         ''),
    40: ('if-modified-since',''),
    41: ('if-none-match',    ''),
    42: ('if-range',         ''),
    43: ('if-unmodified-since', ''),
    44: ('last-modified',    ''),
    45: ('link',             ''),
    46: ('location',         ''),
    47: ('max-forwards',     ''),
    48: ('proxy-authenticate',''),
    49: ('proxy-authorization',''),
    50: ('range',            ''),
    51: ('referer',          ''),
    52: ('refresh',          ''),
    53: ('retry-after',      ''),
    54: ('server',           ''),
    55: ('set-cookie',       ''),
    56: ('strict-transport-security', ''),
    57: ('transfer-encoding',''),
    58: ('user-agent',       ''),
    59: ('vary',             ''),
    60: ('via',              ''),
    61: ('www-authenticate', ''),
}

# RFC 7541 Appendix B — Huffman code table as (code, num_bits) indexed by symbol (0–255 + EOS=256)
_HUFFMAN_TABLE: List[Tuple[int, int]] = [
    (0x1ff8,13),(0x7fffd8,23),(0xfffffe2,28),(0xfffffe3,28),(0xfffffe4,28),
    (0xfffffe5,28),(0xfffffe6,28),(0xfffffe7,28),(0xfffffe8,28),(0xffffea,24),
    (0x3ffffffc,30),(0xfffffe9,28),(0xfffffea,28),(0x3ffffffd,30),(0xfffffeb,28),
    (0xfffffec,28),(0xfffffed,28),(0xfffffee,28),(0xfffffef,28),(0xffffff0,28),
    (0xffffff1,28),(0xffffff2,28),(0x3ffffffe,30),(0xffffff3,28),(0xffffff4,28),
    (0xffffff5,28),(0xffffff6,28),(0xffffff7,28),(0xffffff8,28),(0xffffff9,28),
    (0xffffffa,28),(0xffffffb,28),
    # 32–47 (printable)
    (0x14,6),(0x3f8,10),(0x3f9,10),(0xffa,12),(0x1ff9,13),(0x15,6),(0xf8,8),(0x7fa,11),
    (0x3fa,10),(0x3fb,10),(0xf9,8),(0x7fb,11),(0xfa,8),(0x16,6),(0x17,6),(0x18,6),
    # 48–63 ('0'–'?' / digits and punctuation)
    (0x0,5),(0x1,5),(0x2,5),(0x19,6),(0x1a,6),(0x1b,6),(0x1c,6),(0x1d,6),
    (0x1e,6),(0x1f,6),(0x5c,7),(0xfb,8),(0x7ffc,15),(0x20,6),(0xffb,12),(0x3fc,10),
    # 64–79 ('@'–'O')
    (0x1ffa,13),(0x21,6),(0x5d,7),(0x5e,7),(0x5f,7),(0x60,7),(0x61,7),(0x62,7),
    (0x63,7),(0x64,7),(0x65,7),(0x66,7),(0x67,7),(0x68,7),(0x69,7),(0x6a,7),
    # 80–95 ('P'–'_')
    (0x6b,7),(0x6c,7),(0x6d,7),(0x6e,7),(0x6f,7),(0x70,7),(0x71,7),(0x72,7),
    (0xfc,8),(0x73,7),(0xfd,8),(0x1ffb,13),(0x7fff0,19),(0x1ffc,13),(0x3ffd,14),(0x22,6),
    # 96–111 ('`'–'o')
    (0x7ffd,15),(0x3,5),(0x23,6),(0x4,5),(0x24,6),(0x5,5),(0x25,6),(0x26,6),
    (0x27,6),(0x6,5),(0x74,7),(0x75,7),(0x28,6),(0x29,6),(0x2a,6),(0x7,5),
    # 112–127 ('p'–DEL)
    (0x2b,6),(0x76,7),(0x2c,6),(0x8,5),(0x9,5),(0x2d,6),(0x77,7),(0x78,7),
    (0x79,7),(0x7a,7),(0x7b,7),(0x7ffe,15),(0x7fc,11),(0x3ffe,14),(0x7fd,11),(0x1ffd,13),
    # 128–143
    (0xffffffc,28),(0xfffe6,20),(0x3fffd2,22),(0xfffe7,20),(0xfffe8,20),(0x3fffd3,22),
    (0x3fffd4,22),(0x3fffd5,22),(0x7fffd9,23),(0x3fffd6,22),(0x7fffda,23),(0x7fffdb,23),
    (0x7fffdc,23),(0x7fffdd,23),(0x7fffde,23),(0xffffeb,24),
    # 144–159
    (0x7fffdf,23),(0xffffec,24),(0xffffed,24),(0x3fffd7,22),(0x7fffe0,23),(0xffffee,24),
    (0x7fffe1,23),(0x7fffe2,23),(0x7fffe3,23),(0x7fffe4,23),(0x1fffdc,21),(0x3fffd8,22),
    (0x7fffe5,23),(0x3fffd9,22),(0x7fffe6,23),(0x7fffe7,23),
    # 160–175
    (0xffffef,24),(0x3fffda,22),(0x1fffdd,21),(0xfffe9,20),(0x3fffdb,22),(0x3fffdc,22),
    (0x7fffe8,23),(0x7fffe9,23),(0x1fffde,21),(0x7fffea,23),(0x3fffdd,22),(0x3fffde,22),
    (0xfffff0,24),(0x1fffdf,21),(0x3fffdf,22),(0x7fffeb,23),
    # 176–191
    (0x7fffec,23),(0x1fffe0,21),(0x1fffe1,21),(0x3fffe0,22),(0x1fffe2,21),(0x7fffed,23),
    (0x3fffe1,22),(0x7fffee,23),(0x7fffef,23),(0xfffea,20),(0x3fffe2,22),(0x3fffe3,22),
    (0x3fffe4,22),(0x7ffff0,23),(0x3fffe5,22),(0x3fffe6,22),
    # 192–207
    (0x7ffff1,23),(0x3ffffe0,26),(0x3ffffe1,26),(0xfffeb,20),(0x7fff1,19),(0x3fffe7,22),
    (0x7ffff2,23),(0x3fffe8,22),(0x1ffffec,25),(0x3ffffe2,26),(0x3ffffe3,26),(0x3ffffe4,26),
    (0x7ffffde,27),(0x7ffffdf,27),(0x3ffffe5,26),(0xfffff1,24),
    # 208–223
    (0x1ffffed,25),(0x7fff2,19),(0x1fffe3,21),(0x3ffffe6,26),(0x7ffffe0,27),(0x7ffffe1,27),
    (0x3ffffe7,26),(0x7ffffe2,27),(0xfffff2,24),(0x1fffe4,21),(0x1fffe5,21),(0x3ffffe8,26),
    (0x3ffffe9,26),(0xffffffd,28),(0x7ffffe3,27),(0x7ffffe4,27),
    # 224–239
    (0x7ffffe5,27),(0xfffec,20),(0xfffff3,24),(0xfffed,20),(0x1fffe6,21),(0x3fffe9,22),
    (0x1fffe7,21),(0x1fffe8,21),(0x7ffff3,23),(0x3fffea,22),(0x3fffeb,22),(0x1ffffee,25),
    (0x1ffffef,25),(0xfffff4,24),(0xfffff5,24),(0x3ffffea,26),
    # 240–255
    (0x7ffff4,23),(0x3ffffeb,26),(0x7ffffe6,27),(0x3ffffec,26),(0x3ffffed,26),(0x7ffffe7,27),
    (0x7ffffe8,27),(0x7ffffe9,27),(0x7ffffea,27),(0x7ffffeb,27),(0xfffffe,28),(0x7ffffec,27),
    (0x7ffffed,27),(0x7ffffee,27),(0x7ffffef,27),(0x7fffff0,27),
    (0x3ffffee, 26),  # 256 — EOS
]

# Reverse lookup built lazily: (code, bits) -> symbol
_HUFFMAN_REVERSE: Dict[Tuple[int, int], int] = {}


def _huffman_decode(data: bytes) -> bytes:
    """Decode RFC 7541 Huffman-encoded bytes (Appendix B)."""
    global _HUFFMAN_REVERSE
    if not _HUFFMAN_REVERSE:
        _HUFFMAN_REVERSE = {(code, bits): sym
                            for sym, (code, bits) in enumerate(_HUFFMAN_TABLE)}
    # Convert bytes to a bit-string, then scan for matching codes.
    bits_str = ''.join(format(b, '08b') for b in data)
    result = bytearray()
    i = 0
    n = len(bits_str)
    while i < n:
        matched = False
        for length in range(5, min(31, n - i + 1)):
            code = int(bits_str[i:i + length], 2)
            sym = _HUFFMAN_REVERSE.get((code, length))
            if sym is not None:
                if sym == 256:  # EOS padding
                    return bytes(result)
                result.append(sym)
                i += length
                matched = True
                break
        if not matched:
            break  # remaining bits are EOS padding (all 1s)
    return bytes(result)


# ---------------------------------------------------------------------------
# Frame building helpers
# ---------------------------------------------------------------------------

def build_frame(frame_type: int, flags: int, stream_id: int,
                payload: bytes) -> bytes:
    """Pack a 9-byte HTTP/2 frame header followed by payload.

    Frame format (RFC 7540 §4.1 / http2_header struct in http2.h):
      Length  (24 bits) — payload size
      Type    ( 8 bits)
      Flags   ( 8 bits)
      R + Stream ID (1 + 31 bits)
    """
    length = len(payload)
    hdr = bytes([
        (length >> 16) & 0xff,
        (length >>  8) & 0xff,
         length        & 0xff,
        frame_type & 0xff,
        flags      & 0xff,
    ]) + struct.pack('!I', stream_id & 0x7fffffff)
    return hdr + payload


def build_settings_frame(settings: Optional[Dict[int, int]] = None,
                         ack: bool = False) -> bytes:
    """Build a SETTINGS frame.

    Default parameters mirror magic_settings[] in inject_http2.c:
      MAX_CONCURRENT_STREAMS=100, INITIAL_WINDOW_SIZE=65535,
      HEADER_TABLE_SIZE=4096, ENABLE_PUSH=0, MAX_HEADER_LIST_SIZE=2000
    """
    if ack:
        return build_frame(FRAME_SETTINGS, FLAG_ACK, 0, b'')

    if settings is None:
        settings = {
            SETTINGS_MAX_CONCURRENT_STREAMS: 100,
            SETTINGS_INITIAL_WINDOW_SIZE:    65535,
            SETTINGS_HEADER_TABLE_SIZE:      4096,
            SETTINGS_ENABLE_PUSH:            0,
            SETTINGS_MAX_HEADER_LIST_SIZE:   2000,
        }
    payload = b''.join(struct.pack('!HI', k, v) for k, v in settings.items())
    return build_frame(FRAME_SETTINGS, 0, 0, payload)


def build_window_update_frame(increment: int, stream_id: int = 0) -> bytes:
    """Build a WINDOW_UPDATE frame (HTTP2_INJECT_WIN_UPDATE in http2.h)."""
    payload = struct.pack('!I', increment & 0x7fffffff)
    return build_frame(FRAME_WINDOW_UPDATE, 0, stream_id, payload)


def build_rst_stream_frame(stream_id: int, error_code: int = H2_CANCEL) -> bytes:
    """Build a RST_STREAM frame to abort a stream."""
    return build_frame(FRAME_RST_STREAM, 0, stream_id,
                       struct.pack('!I', error_code))


# ---------------------------------------------------------------------------
# HPACK encoding  (literal representation without indexing — RFC 7541 §6.2.2)
# ---------------------------------------------------------------------------

def _hpack_int(value: int, prefix_bits: int) -> bytes:
    """Encode an integer with a given N-bit prefix (RFC 7541 §5.1)."""
    max_first = (1 << prefix_bits) - 1
    if value < max_first:
        return bytes([value])
    result = [max_first]
    value -= max_first
    while value >= 128:
        result.append((value & 0x7f) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def _hpack_string(s: bytes) -> bytes:
    """HPACK string literal without Huffman (RFC 7541 §5.2).

    Huffman bit = 0, length encoded with 7-bit prefix integer.
    """
    length_bytes = _hpack_int(len(s), 7)
    # length_bytes[0] has the Huffman bit already zero
    return length_bytes + s


def hpack_encode(headers: List[Tuple[str, str]]) -> bytes:
    """Encode a header list using HPACK literal-without-indexing (§6.2.2).

    Representation prefix 0x00 means:
      - no indexing (dynamic table stays unchanged across connections)
      - new name (no static-table name reference)
    This is the safest encoding for fuzz traffic where the dynamic table
    state is unknown or reset on each TCP connection.
    """
    result = b''
    for name, value in headers:
        n = name.encode('latin-1') if isinstance(name, str) else name
        v = value.encode('latin-1') if isinstance(value, str) else value
        result += b'\x00' + _hpack_string(n) + _hpack_string(v)
    return result


def build_headers_frame(stream_id: int,
                        headers: List[Tuple[str, str]],
                        end_stream: bool = False) -> bytes:
    """Build an HTTP/2 HEADERS frame carrying HPACK-encoded headers."""
    payload = hpack_encode(headers)
    flags   = FLAG_END_HEADERS
    if end_stream:
        flags |= FLAG_END_STREAM
    return build_frame(FRAME_HEADERS, flags, stream_id, payload)


def build_data_frame(stream_id: int, data: bytes,
                     end_stream: bool = True) -> bytes:
    """Build an HTTP/2 DATA frame."""
    flags = FLAG_END_STREAM if end_stream else 0
    return build_frame(FRAME_DATA, flags, stream_id, data)


# ---------------------------------------------------------------------------
# HPACK response decoding  (extracts :status and content-type)
# ---------------------------------------------------------------------------

def _hpack_decode_string(data: bytes, offset: int) -> Tuple[bytes, int]:
    """Decode one HPACK string literal starting at offset.

    Returns (string_bytes, new_offset).
    """
    if offset >= len(data):
        return b'', offset
    huffman = bool(data[offset] & 0x80)
    length  = data[offset] & 0x7f
    # Multi-byte length — RFC 7541 §5.1 varint with 7-bit prefix
    if length == 0x7f:
        offset += 1
        shift = 0
        while offset < len(data) and (data[offset] & 0x80):
            length += (data[offset] & 0x7f) << shift
            shift  += 7
            offset += 1
        if offset < len(data):
            length += data[offset] << shift
    offset += 1
    end = offset + length
    s = data[offset:end]
    if huffman:
        try:
            s = _huffman_decode(s)
        except Exception:
            pass  # return raw bytes; caller handles latin-1 decode
    return s, end


def hpack_decode_headers(data: bytes) -> Dict[str, str]:
    """Decode HPACK-encoded response headers into a dict.

    Handles:
    - Indexed header field (static table, RFC 7541 §6.1)
    - Literal with incremental indexing (§6.2.1)
    - Literal without indexing / never indexed (§6.2.2 / §6.2.3)
    """
    headers: Dict[str, str] = {}
    i = 0
    dyn_table: List[Tuple[str, str]] = []  # dynamic table (server side)

    def _get_entry(idx: int) -> Tuple[str, str]:
        if 1 <= idx <= 61:
            e = _HPACK_STATIC.get(idx, ('', ''))
            return e
        dyn_idx = idx - 62
        if dyn_idx < len(dyn_table):
            return dyn_table[dyn_idx]
        return ('', '')

    while i < len(data):
        byte = data[i]

        # -- Dynamic Table Size Update (§6.3): 001xxxxx ---------------------
        if (byte & 0xe0) == 0x20:
            # Decode the new max size (5-bit prefix integer) and skip it.
            new_max = byte & 0x1f
            i += 1
            if new_max == 0x1f:
                shift = 0
                while i < len(data) and (data[i] & 0x80):
                    new_max += (data[i] & 0x7f) << shift
                    shift   += 7
                    i       += 1
                if i < len(data):
                    new_max += data[i]
                    i       += 1
            continue

        # -- Indexed Header Field (§6.1): high bit set ----------------------
        if byte & 0x80:
            # 7-bit index
            idx = byte & 0x7f
            if idx == 0x7f:
                # multi-byte (rare for static table)
                i += 1
                extra = 0
                shift = 0
                while i < len(data) and (data[i] & 0x80):
                    extra += (data[i] & 0x7f) << shift
                    shift += 7
                    i += 1
                if i < len(data):
                    extra += data[i] << shift
                idx = 0x7f + extra
            name, value = _get_entry(idx)
            if name:
                headers[name] = value
            i += 1
            continue

        # -- Literal with Incremental Indexing (§6.2.1): 01xxxxxx ----------
        if byte & 0x40:
            name_idx = byte & 0x3f
            i += 1
            if name_idx == 0x3f:  # max 6-bit value → multi-byte integer (RFC 7541 §5.1)
                shift = 0
                while i < len(data) and (data[i] & 0x80):
                    name_idx += (data[i] & 0x7f) << shift
                    shift += 7
                    i += 1
                if i < len(data):
                    name_idx += data[i] << shift
                    i += 1
            if name_idx == 0:
                name_raw, i = _hpack_decode_string(data, i)
                name = name_raw.decode('latin-1', errors='replace')
            else:
                name, _ = _get_entry(name_idx)
            value_raw, i = _hpack_decode_string(data, i)
            value = value_raw.decode('latin-1', errors='replace')
            headers[name] = value
            dyn_table.insert(0, (name, value))
            continue

        # -- Literal without Indexing (§6.2.2): 0000xxxx ------------------
        # -- Never Indexed (§6.2.3):            0001xxxx ------------------
        name_idx = byte & 0x0f
        i += 1
        if name_idx == 0x0f:  # max 4-bit value → multi-byte integer (RFC 7541 §5.1)
            shift = 0
            while i < len(data) and (data[i] & 0x80):
                name_idx += (data[i] & 0x7f) << shift
                shift += 7
                i += 1
            if i < len(data):
                name_idx += data[i] << shift
                i += 1
        if name_idx == 0:
            name_raw, i = _hpack_decode_string(data, i)
            name = name_raw.decode('latin-1', errors='replace')
        else:
            name, _ = _get_entry(name_idx)
        value_raw, i = _hpack_decode_string(data, i)
        value = value_raw.decode('latin-1', errors='replace')
        headers[name] = value

    return headers


# ---------------------------------------------------------------------------
# HTTP/2 response frame parser
# ---------------------------------------------------------------------------

import socket as _socket
import time as _time


def recv_h2_response(sock: '_socket.socket', timeout: float,
                     buf_size: int = 8192) -> bytes:
    """Read from *sock* until a complete HTTP/2 response arrives or *timeout* expires.

    A "complete response" means we have received at least one HEADERS, GOAWAY,
    or RST_STREAM frame (i.e. actual response content, not just SETTINGS).

    Also sends a SETTINGS ACK the first time we see a server SETTINGS frame
    without the ACK flag, which is required by RFC 7540 §6.5 and allows nghttp2
    to pipeline the response without waiting for client acknowledgement.
    """
    data = b''
    acked = False  # have we sent our SETTINGS ACK for the server's SETTINGS?
    deadline = _time.monotonic() + timeout
    _RESPONSE_FRAME_TYPES = {FRAME_HEADERS, FRAME_GOAWAY, FRAME_RST_STREAM}

    while _time.monotonic() < deadline:
        remaining = deadline - _time.monotonic()
        if remaining <= 0:
            break
        sock.settimeout(min(0.1, remaining))
        try:
            chunk = sock.recv(buf_size)
        except _socket.timeout:
            # Check if we already have a response frame before giving up
            frames = parse_frames(data)
            if any(f['type'] in _RESPONSE_FRAME_TYPES for f in frames):
                break
            continue
        if not chunk:
            break
        data += chunk

        frames = parse_frames(data)
        for frame in frames:
            # Send SETTINGS ACK the first time we see a non-ACK SETTINGS frame
            if (frame['type'] == FRAME_SETTINGS
                    and not (frame['flags'] & FLAG_ACK)
                    and not acked):
                try:
                    sock.sendall(build_settings_frame(ack=True))
                    acked = True
                except OSError:
                    pass
            if frame['type'] in _RESPONSE_FRAME_TYPES:
                # Give a short extra window for DATA frames to arrive
                sock.settimeout(min(0.1, max(0, deadline - _time.monotonic())))
                try:
                    extra = sock.recv(buf_size)
                    if extra:
                        data += extra
                except _socket.timeout:
                    pass
                return data

    return data


def parse_frames(data: bytes) -> List[Dict]:
    """Split a byte stream into HTTP/2 frames.

    Returns list of dicts: {type, flags, stream_id, payload}.
    Incomplete trailing frames are silently discarded.
    """
    frames = []
    i = 0
    while i + 9 <= len(data):
        length = (data[i] << 16) | (data[i+1] << 8) | data[i+2]
        ftype  = data[i+3]
        flags  = data[i+4]
        sid    = struct.unpack('!I', data[i+5:i+9])[0] & 0x7fffffff
        i += 9
        if i + length > len(data):
            break
        payload = data[i:i+length]
        i += length
        frames.append({'type': ftype, 'flags': flags,
                       'stream_id': sid, 'payload': payload})
    return frames


def parse_response(data: bytes) -> Dict:
    """Parse HTTP/2 response bytes into a structured result.

    Returns:
      status       — int HTTP status code or None
      headers      — dict of decoded response headers
      body         — bytes accumulated from DATA frames
      frame_types  — list of all frame type ints seen
      goaway       — True if GOAWAY frame received
      rst_stream   — True if RST_STREAM received
      h2_error     — HTTP/2 error code (from GOAWAY / RST_STREAM)
      raw          — original bytes
    """
    result: Dict = {
        'status':      None,
        'headers':     {},
        'body':        b'',
        'frame_types': [],
        'goaway':      False,
        'rst_stream':  False,
        'h2_error':    0,
        'raw':         data,
    }
    frames = parse_frames(data)
    for frame in frames:
        ftype = frame['type']
        result['frame_types'].append(ftype)
        pl = frame['payload']

        if ftype == FRAME_HEADERS:
            try:
                flags = frame['flags']
                hpack_data = pl
                pad_len = 0
                if flags & 0x8:  # PADDED flag — first byte is pad length
                    if not hpack_data:
                        continue
                    pad_len    = hpack_data[0]
                    hpack_data = hpack_data[1:]
                if flags & 0x20:  # PRIORITY flag — skip 4-byte dep + 1-byte weight
                    if len(hpack_data) < 5:
                        continue
                    hpack_data = hpack_data[5:]
                if pad_len:
                    hpack_data = hpack_data[:-pad_len] if pad_len < len(hpack_data) else b''
                hdrs = hpack_decode_headers(hpack_data)
                result['headers'].update(hdrs)
                if ':status' in hdrs:
                    try:
                        result['status'] = int(hdrs[':status'])
                    except ValueError:
                        pass
            except Exception as exc:
                logger.warning("HPACK decode error (flags=0x%02x): %s", frame['flags'], exc)

        elif ftype == FRAME_DATA:
            result['body'] += pl

        elif ftype == FRAME_GOAWAY:
            result['goaway'] = True
            if len(pl) >= 8:
                result['h2_error'] = struct.unpack('!I', pl[4:8])[0]

        elif ftype == FRAME_RST_STREAM:
            result['rst_stream'] = True
            if len(pl) >= 4:
                result['h2_error'] = struct.unpack('!I', pl[:4])[0]

    return result


# ---------------------------------------------------------------------------
# High-level request builder
# ---------------------------------------------------------------------------

def build_sbi_request(method: str,
                      path: str,
                      authority: str,
                      body: Optional[bytes] = None,
                      extra_headers: Optional[List[Tuple[str, str]]] = None,
                      stream_id: int = 1,
                      content_type: str = 'application/json',
                      include_preface: bool = True,
                      fuzz_stream_id: Optional[int] = None) -> bytes:
    """Build a complete HTTP/2 SBI request for open5GS.

    Produces bytes that can be sent over a plain TCP socket:
      [H2_PREFACE]              — client connection preface (if include_preface)
      [SETTINGS frame]          — client capabilities
      [HEADERS frame]           — :method, :path, content-type, 3gpp-sbi-* headers
      [DATA frame]              — JSON body (if method is POST/PUT/PATCH)

    This mirrors inject_http2.c's approach of bundling preface + payload into
    a single sendall() rather than the 3-step handshake (_http2_connect calls
    _http2_handshake which requires an intermediate read).  For fuzzing, a
    single sendall() is simpler and still reaches SBI parsing code paths.

    fuzz_stream_id: if set, overrides stream_id in the HEADERS frame.  Used to
    exercise HTTP/2 stream-level invariants (stream_id=0, even IDs, reuse).
    """
    sid = fuzz_stream_id if fuzz_stream_id is not None else stream_id

    headers: List[Tuple[str, str]] = [
        (':method',    method.upper()),
        (':scheme',    'http'),
        (':authority', authority),
        (':path',      path),
        ('user-agent', 'NetworkFuzzer/1.0'),
    ]

    has_body = body is not None and len(body) > 0
    if has_body:
        headers += [
            ('content-type',   content_type),
            ('content-length', str(len(body))),
        ]

    # 3GPP SBI mandatory headers (TS 29.500 §5.5)
    headers += [
        ('3gpp-sbi-target-nf-type', 'NRF'),
        ('accept', 'application/json'),
    ]

    if extra_headers:
        headers.extend(extra_headers)

    headers_frame = build_headers_frame(sid, headers, end_stream=not has_body)
    data_frame    = build_data_frame(sid, body) if has_body else b''

    prefix = (H2_PREFACE + build_settings_frame()) if include_preface else b''
    return prefix + headers_frame + data_frame


# ---------------------------------------------------------------------------
# Fuzz-specific frame builders  (attack primitives)
# ---------------------------------------------------------------------------

def build_fuzz_headers_frame(stream_id: int,
                             headers: List[Tuple[str, str]],
                             end_stream: bool = False,
                             raw_hpack: Optional[bytes] = None) -> bytes:
    """Build a HEADERS frame for fuzzing.

    If raw_hpack is supplied, it is used verbatim as the payload (bypassing
    the HPACK encoder).  This enables HPACK bomb / compression error attacks.
    """
    payload = raw_hpack if raw_hpack is not None else hpack_encode(headers)
    flags   = FLAG_END_HEADERS | (FLAG_END_STREAM if end_stream else 0)
    return build_frame(FRAME_HEADERS, flags, stream_id, payload)


def build_window_amplification(stream_id: int = 1) -> bytes:
    """Build a WINDOW_UPDATE flood sequence (HTTP2_INJECT_WIN_UPDATE, http2.h §15).

    Sends 10 consecutive WINDOW_UPDATE frames on both the connection (stream=0)
    and a specific stream, causing the server to update its flow-control window.
    """
    frames = b''
    for _ in range(10):
        frames += build_window_update_frame(0x3fffffff, 0)
        frames += build_window_update_frame(0x3fffffff, stream_id)
    return frames


def build_header_amplification(stream_id: int = 1) -> bytes:
    """Build a HEADERS amplification attack (HTTP2_HEADER_AMPLIFICATION, http2.h §15).

    Sends a HEADERS frame followed by multiple CONTINUATION frames with empty
    payloads.  The server may try to reassemble them, exercising header-list
    limits (SETTINGS_MAX_HEADER_LIST_SIZE).
    """
    # First HEADERS frame WITHOUT END_HEADERS to start a continuation sequence
    hpack   = hpack_encode([(':method', 'GET'), (':path', '/'), (':scheme', 'http'),
                             (':authority', 'fuzz')])
    headers_frame = build_frame(FRAME_HEADERS, 0, stream_id, hpack)   # no END_HEADERS

    # 16 CONTINUATION frames — last one carries END_HEADERS
    cont = b''.join(
        build_frame(FRAME_CONTINUATION,
                    FLAG_END_HEADERS if i == 15 else 0,
                    stream_id, b'')
        for i in range(16)
    )
    return headers_frame + cont
