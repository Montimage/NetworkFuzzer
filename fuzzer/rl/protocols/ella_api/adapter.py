#!/usr/bin/env python3
"""
ella REST Management API Adapter for RL fuzzing.

Targets ella-core's HTTPS/2 management API (port 5002, all interfaces).

Attack surface:
  Subscriber CRUD  — POST/PUT/DELETE /api/v1/subscribers/{imsi}
  Radio CRUD       — POST/PUT/DELETE /api/v1/radios/{name}
  Network slices   — POST/PUT/DELETE /api/v1/network-slices/{name}
  Profiles/DevGrp  — POST /api/v1/profiles, /api/v1/device-groups
  Auth bypass      — write requests sent without or with invalid tokens
  Input validation — IMSI format, key length/encoding, TAC range,
                     path traversal, JSON type confusion, body size

Transport:  HTTPS/2 (TLS, skip cert verification, ALPN h2)
Auth:       None by default (tests auth bypass); set api_token field for valid auth.
Core:       ella-core v1.10+ (single binary: AMF+SMF+UPF+UDM+NRF)

Usage:
    python -m fuzzer.rl.train_protocol --protocol ella_api \\
        --core ella --target-host 10.3.0.2 --target-port 5002 \\
        --timesteps 50000 --max-steps 20
"""

import json
import struct
import time
import logging
from urllib.parse import quote as _url_quote
from typing import Any, Dict, List, Optional, Tuple

from fuzzer.rl.base.protocol_adapter import (
    ProtocolAdapter,
    FieldDefinition,
    FuzzScenario,
    StateTransition,
    PayloadTarget,
    HealthCheckResult,
    register_protocol,
)
from fuzzer.rl.protocols.sbi.http2_client import (
    build_sbi_request,
    recv_h2_response,
    parse_response as _parse_h2,
    H2_PREFACE,
    build_settings_frame,
    build_headers_frame,
    build_data_frame,
    hpack_encode,
    FRAME_HEADERS,
    FRAME_DATA,
)
from fuzzer.rl.monitor import NfMonitor

logger = logging.getLogger(__name__)

# ── Baseline valid field values ───────────────────────────────────────────────

_VALID_IMSI  = "001010123456789"
_VALID_KEY   = "465B5CE8B199B49FAA5F0A2EE238A6BC"
_VALID_OPC   = "E8ED289DEBA952E4283B54E88E6183CA"
_VALID_SEQ   = "16f3b3f70fc2"
_VALID_DNN   = "internet"
_VALID_SLICE  = "slice-fuzz"
_VALID_POLICY = "policy-fuzz"
_VALID_PROF   = "prof-fuzz"

# ── IMSI attack/boundary values ───────────────────────────────────────────────

_IMSI_VALUES: List[Any] = [
    "001010123456789",           # valid baseline
    "001010000000001",           # valid minimal
    "999999999999999",           # max IMSI (15 nines)
    "000000000000000",           # all-zeros IMSI
    "",                          # empty string — expect 400/422
    "0",                         # too short (1 digit)
    "9" * 20,                    # too long (20 digits)
    "imsi-001010123456789",      # 3GPP SUPI-format prefix — parser confusion
    "001010\x00injected",        # null-byte injection
    "'; DROP TABLE subscribers; --",  # SQL injection probe (dqlite)
    "../../../etc/passwd",       # path traversal as IMSI
    "001010" + "A" * 200,        # oversized (200+ chars)
    "%00%0a%0d",                 # URL-encoded control chars
    "001010123456789\n",         # trailing newline
    "￿",              # unicode extremes
]

# ── Authentication header values ──────────────────────────────────────────────
# None = omit Authorization entirely (auth bypass probe)

_AUTH_VALUES: List[Optional[str]] = [
    None,                                   # no header — auth bypass probe (highest value)
    "Bearer eyJhbGciOiJub25lIn0.e30.",      # JWT alg:none bypass (CVE class)
]

# ── 5QI (var5qi) boundary values ─────────────────────────────────────────────
# var5qi is a policy QoS flow identifier; valid standardized values are 1–86.

_VAR5QI_VALUES: List[Any] = [1, 5, 9, 65, 86, 0, 255, 256, -1, 87, "abc", None, 2**31 - 1]

# ── Authentication key boundary values ───────────────────────────────────────

_KEY_VALUES: List[str] = [
    "465B5CE8B199B49FAA5F0A2EE238A6BC",       # valid 128-bit
    "00000000000000000000000000000000",       # all-zero key
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",       # all-ones key
    "",                                        # empty
    "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",       # non-hex chars
    "465B5CE8",                               # too short (32-bit)
    "465B5CE8B199B49F" * 8,                   # too long (512-bit)
    "null",                                    # JSON null as string
]

# ── Slice service type boundary values ───────────────────────────────────────

_SST_VALUES: List[Any] = [1, 2, 3, 0, 255, -1, 256, "embb", None]

# ── Content-Type confusion values ────────────────────────────────────────────

_CTYPE_VALUES: List[str] = [
    "application/json",
    "text/plain",
    "application/x-www-form-urlencoded",
    "application/octet-stream",
    "application/json; boundary=evil",
    "",
    "application/json\x00",
]

# ── HTTP method confusion values ─────────────────────────────────────────────

_METHOD_VALUES: List[str] = [
    "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE",
    "CONNECT", "HEAD", "FUZZ", "GET\x00POST",
]

# ── Email boundary values (auth/login fuzzing) ────────────────────────────────
# Based on GHSA-87j9 pattern: input not sanitised before use in DB queries

_EMAIL_VALUES: List[str] = [
    "fuzz@test.com",                        # valid account
    "admin@ella.local",                     # common default admin address
    "' OR '1'='1",                          # classic SQL injection
    "' OR '1'='1'--",                       # SQL injection with comment
    "'; DROP TABLE users; --",              # destructive SQLi
    "\" OR \"1\"=\"1",                      # double-quote SQLi variant
    "admin@ella.local'--",                  # comment-based SQLi
    "a" * 256 + "@test.com",               # oversized email
    "",                                     # empty
    "\x00admin@test.com",                   # null byte prefix
    "not-an-email",                         # malformed
    "user@[127.0.0.1]",                    # IP literal
]

_PASSWORD_VALUES: List[str] = [
    "password123",                          # weak password probe
    "' OR '1'='1",                          # SQLi in password
    "",                                     # empty password
    "a" * 1024,                            # oversized
    "\x00\xff\xfe",                        # binary data
    "password\n",                           # trailing newline
]

# ── Minimal crafted SQLite for backup/restore fuzzing ────────────────────────
# SQLite3 file header magic (first 16 bytes). Used in restore endpoint fuzzing.
# GHSA-87j9: restore accepted any valid SQLite without integrity checks.
_SQLITE_MAGIC = b"SQLite format 3\x00"
# Minimal 1-page SQLite DB (empty schema) — just the 100-byte file header
_SQLITE_MINIMAL = _SQLITE_MAGIC + b"\x10\x00" + b"\x01\x01\x00\x40\x20\x20" + b"\x00" * 92
# Crafted SQLite claiming to be a DB with an admin user (not real pages — triggers parser)
_SQLITE_CRAFTED_HEADER = _SQLITE_MAGIC + b"\xff\xff" + b"\x00" * 98


# ── Body builders ─────────────────────────────────────────────────────────────

def _subscriber_body(imsi=_VALID_IMSI, key=_VALID_KEY, opc=_VALID_OPC,
                     seq=_VALID_SEQ, dnn=_VALID_DNN) -> bytes:
    return json.dumps({
        "imsi": imsi, "key": key, "opc": opc,
        "sequenceNumber": seq,        # ella uses camelCase
        "profile_name": "default",    # required by ella
    }).encode()

def _slice_body(name=_VALID_SLICE, sst=1, sd="000001") -> bytes:
    return json.dumps({"name": name, "sst": sst, "sd": sd}).encode()

def _policy_body(name=_VALID_POLICY, var5qi=9, arp=1) -> bytes:
    # ella policy fields (confirmed from API introspection)
    return json.dumps({
        "name": name,
        "profile_name": "default",
        "slice_name": "default",
        "data_network_name": "internet",
        "session_ambr_uplink":   "100 Mbps",
        "session_ambr_downlink": "100 Mbps",
        "var5qi": var5qi,
        "arp": arp,
    }).encode()

def _profile_body(name=_VALID_PROF, uplink="100 Mbps", downlink="100 Mbps") -> bytes:
    return json.dumps({
        "name": name,
        "ue_ambr_uplink":   uplink,
        "ue_ambr_downlink": downlink,
    }).encode()

def _user_body(email="fuzz-user@test.com", role_id=1) -> bytes:
    return json.dumps({"email": email, "roleId": role_id, "password": "Password1!"}).encode()

def _route_body(destination="10.200.0.0/24", nexthop="10.0.0.1") -> bytes:
    return json.dumps({"destination": destination, "nexthop": nexthop}).encode()

def _bgp_peer_body(address="10.200.0.1", asn=65001) -> bytes:
    return json.dumps({"address": address, "asn": asn}).encode()

def _retention_body(days=30) -> bytes:
    return json.dumps({"days": days}).encode()

def _operator_body() -> bytes:
    return json.dumps({
        "mcc": "001", "mnc": "01",
        "integrityProtectionAlgorithm": 2,
        "cipheringAlgorithm": 0,
    }).encode()

def _n3_body(address="10.0.0.1") -> bytes:
    return json.dumps({"address": address}).encode()

def _nat_body(enabled=True) -> bytes:
    return json.dumps({"enabled": enabled}).encode()

def _flow_accounting_body(enabled=True, sample_rate=1) -> bytes:
    return json.dumps({"enabled": enabled, "sampleRate": sample_rate}).encode()

# ── New boundary value lists ──────────────────────────────────────────────────

_FUZZ_USER_EMAIL   = "fuzz-user@test.com"
_FUZZ_ROUTE_ID     = "fuzz-route-1"
_FUZZ_BGP_PEER_IP  = "10.200.0.1"
_FUZZ_JOIN_TOKEN_ID = "fuzz-jt-1"
_FUZZ_CLUSTER_MEMBER = "fuzz-node-1"

_BGP_ASN_VALUES: List[Any] = [65001, 65535, 1, 0, -1, 4294967295, 4294967296, "abc", None]
_CIDR_VALUES: List[str] = [
    "10.200.0.0/24", "0.0.0.0/0", "192.168.0.0/16",
    "", "256.0.0.0/8", "10.0.0.1/33", "::1/128",
]
_RETENTION_DAY_VALUES: List[Any] = [7, 30, 90, 365, 0, -1, 9999999, "abc", None]
_USER_ROLE_VALUES: List[Any] = [1, 2, 0, -1, 255, "admin", "superadmin", None]

# ── Low-level H2 request builder ──────────────────────────────────────────────

def _safe_path(raw: str) -> str:
    """Percent-encode characters that HPACK cannot encode as latin-1.

    HTTP/2 :path must be ASCII (RFC 7540 §8.1.2.3).  Attack values like
    U+FFFF or null bytes need to be URL-encoded so hpack_encode() doesn't
    raise UnicodeEncodeError.  Preserves /, ?, =, &, - deliberately.
    """
    return _url_quote(raw, safe="/:@!$&'()*+,;=?-%.")


def _safe_header(raw: str) -> str:
    """Replace non-latin-1 chars in a header value with their hex escapes.

    HPACK encodes header values as latin-1.  Chars outside U+00FF are
    replaced with \\uXXXX so the fuzz attempt reaches ella's parser
    without crashing the encoder.
    """
    return raw.encode("latin-1", errors="xmlcharrefreplace").decode("latin-1")


def _build_request(method: str, path: str, authority: str,
                   body: Optional[bytes] = None,
                   content_type: str = "application/json",
                   auth: Optional[str] = None) -> bytes:
    """Build a complete HTTPS/2 request for ella's REST API.

    Produces H2_PREFACE + SETTINGS + HEADERS + (DATA if body present).
    TLS wrapping is handled by generic_env._tls_upgrade().
    """
    headers: List[Tuple[str, str]] = [
        (":method",    _safe_header(method.upper())),
        (":scheme",    "https"),
        (":authority", authority),
        (":path",      _safe_path(path)),
        ("accept",     "application/json"),
        ("user-agent", "NetworkFuzzer/1.0"),
    ]
    has_body = bool(body)
    if has_body:
        headers += [
            ("content-type",   _safe_header(content_type)),
            ("content-length", str(len(body))),
        ]
    if auth is not None:
        headers.append(("authorization", _safe_header(auth)))

    headers_frame = build_headers_frame(1, headers, end_stream=not has_body)
    data_frame    = build_data_frame(1, body) if has_body else b""
    return H2_PREFACE + build_settings_frame() + headers_frame + data_frame


# ── Protocol adapter ──────────────────────────────────────────────────────────

@register_protocol("ella_api")
class EllaApiAdapter(ProtocolAdapter):
    """RL fuzzing adapter for ella-core's REST management API."""

    # Credentials for automatic JWT refresh (matches _seed_db fuzz user)
    _FUZZ_EMAIL    = "fuzz@test.com"
    _FUZZ_PASSWORD = "password123"

    def __init__(self,
                 log_path: str = "/tmp/ella-logs/cored.log",
                 core: str = "ella",
                 api_token: Optional[str] = None,
                 **_kwargs):
        self._log_path  = log_path
        self._core      = core
        # Passed token is used only as a hint that we WANT auth. We always
        # do a fresh login on the first request because ella rotates its JWT
        # signing secret during startup, invalidating any token obtained before
        # leadership/db initialisation completes.
        self._api_token = api_token
        self._token_exp: float = 0.0          # Unix timestamp of current JWT expiry
        self._initial_login_done: bool = False  # force fresh login on first call
        self._login_retry_after: float = 0.0   # backoff: don't retry before this time
        self._login_fail_count: int = 0        # consecutive failures; used for escalating logs
        # Learned from build_message; used by cleanup in reset_episode
        self._target_host: str = ""
        self._target_port: int = self.default_port

        self._monitor = NfMonitor(
            core=core,
            primary_nf="AMF",
            log_path=log_path,
        )
        # Track per-episode response novelty for bonus rewards
        self._episode_status_set: set = set()
        # Track per-episode read operation counts for diminishing returns
        self._episode_read_counts: Dict[str, int] = {}
        # Track per-episode write operation counts for diminishing returns
        self._episode_write_counts: Dict[str, int] = {}
        # Set by build_message so compute_reward knows what type was sent
        self._last_message_type: str = ""
        # Set by compute_reward so encode_observation can encode last response
        self._last_response_type: str = ""

    def reset_episode(self) -> None:
        self._cleanup_fuzz_resources()
        self._episode_status_set.clear()
        self._episode_read_counts.clear()
        self._episode_write_counts.clear()
        self._last_message_type = ""
        self._last_response_type = ""
        self._monitor.reset_episode()

    # ── Identity ──────────────────────────────────────────────────────────────

    @property
    def protocol_name(self) -> str:
        return "ella_api"

    @property
    def default_port(self) -> int:
        return 5002

    # ── Connection ────────────────────────────────────────────────────────────

    def get_connection_params(self) -> Dict[str, Any]:
        return {"socket_type": "tcp", "tcp_nodelay": True, "use_tls": True}

    def recv_data(self, sock: Any, timeout: float, buf_size: int = 8192) -> bytes:
        return recv_h2_response(sock, timeout=timeout, buf_size=max(buf_size, 8192))

    # ── Semantic fields ───────────────────────────────────────────────────────

    def get_semantic_fields(self) -> List[FieldDefinition]:
        return [
            FieldDefinition("imsi",         None, None, "string",
                            valid_values=[_VALID_IMSI],
                            boundary_values=_IMSI_VALUES,
                            description="Subscriber IMSI (15-digit string)"),
            FieldDefinition("key",          None, None, "string",
                            valid_values=[_VALID_KEY],
                            boundary_values=_KEY_VALUES,
                            description="SIM authentication key (32 hex chars)"),
            FieldDefinition("var5qi",       None, None, "uint8",
                            valid_values=[1, 5, 9],
                            boundary_values=_VAR5QI_VALUES,
                            description="5QI QoS class for policy (1–255)"),
            FieldDefinition("sst",          None, None, "uint8",
                            valid_values=[1, 2, 3],
                            boundary_values=_SST_VALUES,
                            description="Slice/Service Type"),
            FieldDefinition("auth_mode",    None, None, "string",
                            valid_values=[],   # intentionally empty: falls through to
                                               # baseline_fields (valid JWT token) by
                                               # default; None appears only in mutations
                            boundary_values=_AUTH_VALUES,
                            description="Authorization header value (None=omit)"),
            FieldDefinition("email",         None, None, "string",
                            valid_values=["fuzz@test.com"],
                            boundary_values=_EMAIL_VALUES,
                            description="User email for auth/login endpoint (SQLi target)"),
            FieldDefinition("password",      None, None, "string",
                            valid_values=["password123"],
                            boundary_values=_PASSWORD_VALUES,
                            description="User password for auth/login endpoint"),
            FieldDefinition("content_type", None, None, "string",
                            valid_values=["application/json"],
                            boundary_values=_CTYPE_VALUES,
                            description="Content-Type header"),
            FieldDefinition("http_method",  None, None, "string",
                            valid_values=["POST", "PUT", "DELETE"],
                            boundary_values=_METHOD_VALUES,
                            description="HTTP method for method-confusion attacks"),
        ]

    def get_mutation_values(self, field_name: str) -> List[Any]:
        # email/password intentionally excluded: auth_login with wrong creds always
        # returns 401 regardless of mutation — no handler depth signal.
        # SQLi against auth is covered by the login_sqli_probe scenario instead.
        table = {
            "imsi":         _IMSI_VALUES,
            "key":          _KEY_VALUES,
            "var5qi":       _VAR5QI_VALUES,
            "sst":          _SST_VALUES,
            "content_type": _CTYPE_VALUES,
            "http_method":  _METHOD_VALUES,
        }
        return table.get(field_name, [])

    # ── Message types ─────────────────────────────────────────────────────────

    def get_message_types(self) -> List[str]:
        return [
            # Subscriber CRUD (primary attack surface — dqlite write path)
            "subscriber_create",
            "subscriber_update",
            "subscriber_delete",
            "subscriber_get",
            "subscriber_list",
            # Network slice CRUD  (/api/v1/slices)
            "slice_create",
            "slice_update",
            "slice_delete",
            "slice_list",
            # Policy CRUD  (/api/v1/policies)  — replaces radio write ops
            # ella has no REST API to create radios; gNBs auto-register via NGAP
            "policy_create",
            "policy_update",
            "policy_delete",
            "policy_list",
            # Profile CRUD  (/api/v1/profiles)
            "profile_create",
            "profile_list",
            # Radio read-only  (/api/v1/ran/radios — GET only, gNBs auto-register)
            "radio_list",
            # Special attack messages
            "path_traversal",       # IMSI-like path with traversal chars
            "method_confusion",     # Wrong HTTP method on known endpoint
            "large_body",           # 1 MB+ body → OOM / parser limits
            "empty_body_post",      # POST with zero-length body
            "type_confusion",       # JSON array instead of object
            "deep_nesting",         # {a:{b:{c:{...}}}} stack overflow probe
            # Auth endpoints
            "auth_login",               # POST /api/v1/auth/login — SQLi in email/password
            "auth_lookup_token",        # POST /api/v1/auth/lookup-token — token validation bypass
            # auth_rotate_secret excluded: 100pt reward caused agent to spam it, cascading 401 loops
            # Subscriber sub-resources
            "subscriber_credentials",   # GET /api/v1/subscribers/{imsi}/credentials — key exposure
            "subscriber_imsi_mismatch", # PUT path IMSI ≠ body IMSI — audit log falsification (GHSA-xw45)
            # Backup/restore (GHSA-87j9 — arbitrary SQLite upload → priv-esc)
            "backup_get",               # GET /api/v1/backup — sensitive DB download
            "restore_crafted",          # POST /api/v1/restore — crafted SQLite upload
            # Operator config (high-value: changes MCC/MNC, NAS crypto)
            "operator_get",             # GET /api/v1/operator
            "operator_nas_update",      # PUT /api/v1/operator/nas-security
            # Debug/info-disclosure (should require admin auth)
            "pprof_get",               # GET /api/v1/pprof/ — Go profiling, auth check
            "support_bundle_get",       # GET /api/v1/support-bundle — full log dump
            # Data networks
            "data_network_list",        # GET /api/v1/networking/data-networks
            "data_network_create",      # POST /api/v1/networking/data-networks
            "data_network_update",      # PUT /api/v1/networking/data-networks/{name}
            "data_network_delete",      # DELETE /api/v1/networking/data-networks/{name}
            # Health/setup
            "status_get",
            # Auth (extended)
            "auth_refresh",             # POST /api/v1/auth/refresh — token refresh bypass probe
            "auth_logout",              # POST /api/v1/auth/logout — session invalidation
            "auth_rotate_secret",       # POST /api/v1/auth/rotate-secret — JWT key rotation
            # Users CRUD + API tokens
            "user_list",                # GET /api/v1/users
            "user_create",              # POST /api/v1/users
            "user_get",                 # GET /api/v1/users/{email}
            "user_update",              # PUT /api/v1/users/{email}
            "user_delete",              # DELETE /api/v1/users/{email}
            "user_password_update",     # PUT /api/v1/users/{email}/password
            "user_me_get",              # GET /api/v1/users/me
            "user_me_password",         # PUT /api/v1/users/me/password
            "user_me_tokens_list",      # GET /api/v1/users/me/api-tokens
            "user_me_token_create",     # POST /api/v1/users/me/api-tokens
            "user_me_token_delete",     # DELETE /api/v1/users/me/api-tokens/{id}
            # Init
            "init_post",                # POST /api/v1/init — re-init probe (should fail on live instance)
            # Subscriber usage
            "subscriber_usage_get",            # GET /api/v1/subscriber-usage
            "subscriber_usage_delete",         # DELETE /api/v1/subscriber-usage
            "subscriber_usage_retention_get",  # GET /api/v1/subscriber-usage/retention
            "subscriber_usage_retention_set",  # PUT /api/v1/subscriber-usage/retention
            # Profile get/update/delete (list/create already present above)
            "profile_get",              # GET /api/v1/profiles/{name}
            "profile_update",           # PUT /api/v1/profiles/{name}
            "profile_delete",           # DELETE /api/v1/profiles/{name}
            # Operator full update
            "operator_update",          # PUT /api/v1/operator
            # Networking — routes
            "route_list",               # GET /api/v1/networking/routes
            "route_create",             # POST /api/v1/networking/routes
            "route_delete",             # DELETE /api/v1/networking/routes/{id}
            # Networking — BGP
            "bgp_list",                 # GET /api/v1/networking/bgp
            "bgp_peer_create",          # POST /api/v1/networking/bgp/peers
            "bgp_peer_update",          # PUT /api/v1/networking/bgp/peers/{ip}
            "bgp_peer_delete",          # DELETE /api/v1/networking/bgp/peers/{ip}
            "bgp_advertised_routes",    # GET /api/v1/networking/bgp/advertised-routes
            "bgp_learned_routes",       # GET /api/v1/networking/bgp/learned-routes
            # Networking — NAT / flow-accounting / interfaces / N3
            "nat_get",                  # GET /api/v1/networking/nat
            "nat_update",               # PUT /api/v1/networking/nat
            "flow_accounting_get",      # GET /api/v1/networking/flow-accounting
            "flow_accounting_update",   # PUT /api/v1/networking/flow-accounting
            "interfaces_list",          # GET /api/v1/networking/interfaces
            "n3_get",                   # GET /api/v1/networking/n3
            "n3_update",                # PUT /api/v1/networking/n3
            # RAN events
            "ran_events_list",                 # GET /api/v1/ran/events
            "ran_events_delete",               # DELETE /api/v1/ran/events
            "ran_events_retention_get",        # GET /api/v1/ran/events/retention
            "ran_events_retention_set",        # PUT /api/v1/ran/events/retention
            "radio_get",                       # GET /api/v1/ran/radios/{name}
            # Flow reports
            "flow_reports_list",               # GET /api/v1/flow-reports
            "flow_reports_delete",             # DELETE /api/v1/flow-reports
            "flow_stats_get",                  # GET /api/v1/flow-reports/stats
            "flow_reports_retention_get",      # GET /api/v1/flow-reports/retention
            "flow_reports_retention_set",      # PUT /api/v1/flow-reports/retention
            # Audit logs
            "audit_logs_list",                 # GET /api/v1/audit-logs
            "audit_logs_retention_get",        # GET /api/v1/audit-logs/retention
            "audit_logs_retention_set",        # PUT /api/v1/audit-logs/retention
            # Metrics
            "metrics_get",                     # GET /api/v1/metrics
            # Cluster
            "cluster_members_list",            # GET /api/v1/cluster/members
            "cluster_member_delete",           # DELETE /api/v1/cluster/members/{name}
            "cluster_member_promote",          # POST /api/v1/cluster/members/{name}/promote
            "cluster_member_drain",            # POST /api/v1/cluster/members/{name}/drain
            "cluster_member_resume",           # POST /api/v1/cluster/members/{name}/resume
            "cluster_autopilot_get",           # GET /api/v1/cluster/autopilot
            "cluster_join_tokens_list",        # GET /api/v1/cluster/pki/join-tokens
            "cluster_join_token_create",       # POST /api/v1/cluster/pki/join-tokens
            "cluster_join_token_delete",       # DELETE /api/v1/cluster/pki/join-tokens/{id}
            # Pprof sub-endpoints
            "pprof_heap",                      # GET /api/v1/pprof/heap
            "pprof_profile",                   # GET /api/v1/pprof/profile
            "pprof_trace",                     # GET /api/v1/pprof/trace
        ]

    def get_field_message_type(self, field_name: str) -> Optional[str]:
        # email/password not mapped — keeps them out of seq_mutation action space.
        return {
            "imsi":         "subscriber_create",
            "key":          "subscriber_create",
            "var5qi":       "policy_create",
            "sst":          "slice_create",
            "content_type": "subscriber_create",
            "http_method":  "policy_list",
        }.get(field_name)

    # ── State transitions ─────────────────────────────────────────────────────

    def get_state_transitions(self) -> List[StateTransition]:
        return [
            # Valid flows (preamble for semantic actions)
            StateTransition(
                "subscriber_create_only",
                ["subscriber_create"],
                "POST /api/v1/subscribers — single create",
                is_valid=True,
            ),
            StateTransition(
                "slice_create_only",
                ["slice_create"],
                "POST /api/v1/slices — single create",
                is_valid=True,
            ),
            StateTransition(
                "policy_create_only",
                ["policy_create"],
                "POST /api/v1/policies — single create",
                is_valid=True,
            ),
            StateTransition(
                "status_only",
                ["status_get"],
                "GET /api/v1/status — baseline health probe",
                is_valid=True,
            ),

            # Invalid / fuzzing sequences
            StateTransition(
                "create_then_update_subscriber",
                ["subscriber_create", "subscriber_update"],
                "POST then PUT same subscriber — update path through dqlite",
                is_valid=False,
            ),
            StateTransition(
                "create_then_delete_subscriber",
                ["subscriber_create", "subscriber_delete"],
                "POST then DELETE — dqlite delete path",
                is_valid=False,
            ),
            StateTransition(
                "double_create_subscriber",
                ["subscriber_create", "subscriber_create"],
                "POST same subscriber twice — duplicate key constraint handling",
                is_valid=False,
            ),
            StateTransition(
                "create_then_get_subscriber",
                ["subscriber_create", "subscriber_get"],
                "POST then GET — round-trip IMSI parsing",
                is_valid=False,
            ),
            StateTransition(
                "auth_bypass_subscriber_list",
                ["subscriber_list"],
                "GET /api/v1/subscribers without token — auth bypass probe",
                is_valid=False,
            ),
            StateTransition(
                "path_traversal_get",
                ["path_traversal"],
                "GET /api/v1/subscribers/../../../etc/passwd",
                is_valid=False,
            ),
            StateTransition(
                "method_confusion_on_policy",
                ["method_confusion"],
                "Unexpected HTTP method on /api/v1/policies",
                is_valid=False,
            ),
            StateTransition(
                "large_body_subscriber",
                ["large_body"],
                "POST with 1 MB body — parser size limit probe",
                is_valid=False,
            ),
            StateTransition(
                "empty_body_create",
                ["empty_body_post"],
                "POST with zero-length body — nil-dereference probe",
                is_valid=False,
            ),
            StateTransition(
                "type_confusion_subscriber",
                ["type_confusion"],
                "POST JSON array instead of object — type assertion panic probe",
                is_valid=False,
            ),
            StateTransition(
                "deep_nesting_probe",
                ["deep_nesting"],
                "POST deeply-nested JSON object — stack overflow probe",
                is_valid=False,
            ),
            StateTransition(
                "policy_then_slice",
                ["policy_create", "slice_create"],
                "Create policy then slice — cross-resource state",
                is_valid=False,
            ),
            StateTransition(
                "full_chain",
                ["slice_create", "policy_create", "subscriber_create",
                 "profile_create"],
                "Full provisioning chain — ella processes all resource types",
                is_valid=False,
            ),
        ]

    # ── Payload targets ───────────────────────────────────────────────────────

    def get_payload_targets(self) -> List[PayloadTarget]:
        return [
            PayloadTarget("json_body",  "body",   max_size=None, encoding="bytes"),
            PayloadTarget("imsi_field", "imsi",   max_size=64,   encoding="string"),
        ]

    def get_priority_payload_types(self) -> List[str]:
        # JSON-focused payloads are more useful than NAS PDUs for a REST API
        return ["null_injection", "buffer_overflow", "nas_5gmm"]

    # ── Scenarios (guaranteed write-path coverage) ────────────────────────────

    def get_scenarios(self) -> List[FuzzScenario]:
        """Pre-sequenced scenarios that guarantee the write path is reachable.

        Setup messages use baseline valid fields so the prerequisite resource
        definitely exists before the fuzz message hits the handler.
        """
        return [
            # ── Subscriber write path ─────────────────────────────────────────
            FuzzScenario(
                name="update_subscriber_after_create",
                target_api="subscriber_write",
                setup_messages=["subscriber_create"],
                fuzz_message="subscriber_update",
                description="Create subscriber with valid baseline, then fuzz PUT "
                            "(exercises dqlite update path)",
                relevant_fields=["imsi", "key"],
            ),
            FuzzScenario(
                name="delete_subscriber_after_create",
                target_api="subscriber_write",
                setup_messages=["subscriber_create"],
                fuzz_message="subscriber_delete",
                description="Create subscriber with valid baseline, then fuzz DELETE",
                relevant_fields=["imsi"],
            ),
            FuzzScenario(
                name="get_subscriber_after_create",
                target_api="subscriber_read",
                setup_messages=["subscriber_create"],
                fuzz_message="subscriber_get",
                description="Create subscriber, then fuzz GET — exercises IMSI parsing "
                            "in the read path",
                relevant_fields=["imsi"],
            ),
            FuzzScenario(
                name="double_create_subscriber",
                target_api="subscriber_write",
                setup_messages=["subscriber_create"],
                fuzz_message="subscriber_create",
                description="Create subscriber, then create again — "
                            "exercises duplicate-key handling in dqlite",
                relevant_fields=["imsi", "key"],
            ),
            # ── Policy write path ─────────────────────────────────────────────
            FuzzScenario(
                name="update_policy_after_create",
                target_api="policy_write",
                setup_messages=["policy_create"],
                fuzz_message="policy_update",
                description="Create policy, then fuzz PUT — exercises policy update path",
                relevant_fields=["var5qi"],
            ),
            FuzzScenario(
                name="delete_policy_after_create",
                target_api="policy_write",
                setup_messages=["policy_create"],
                fuzz_message="policy_delete",
                description="Create policy, then fuzz DELETE",
                relevant_fields=["var5qi"],
            ),
            # ── Slice write path ──────────────────────────────────────────────
            FuzzScenario(
                name="update_slice_after_create",
                target_api="slice_write",
                setup_messages=["slice_create"],
                fuzz_message="slice_update",
                description="Create slice, then fuzz PUT /api/v1/slices",
                relevant_fields=["sst"],
            ),
            # ── Full provisioning chain ───────────────────────────────────────
            FuzzScenario(
                name="full_provisioning_chain",
                target_api="subscriber_write",
                setup_messages=["slice_create", "policy_create", "subscriber_create"],
                fuzz_message="profile_create",
                description="Full provisioning chain — create all resource types",
                relevant_fields=["imsi"],
            ),
            # ── Auth sequences ────────────────────────────────────────────────
            FuzzScenario(
                name="login_sqli_probe",
                target_api="auth",
                setup_messages=[],
                fuzz_message="auth_login",
                description="POST /api/v1/auth/login with mutated email — SQLi probe",
                relevant_fields=["email", "password"],
            ),
            # ── IMSI path/body mismatch (GHSA-xw45) ──────────────────────────
            FuzzScenario(
                name="imsi_mismatch_after_create",
                target_api="subscriber_write",
                setup_messages=["subscriber_create"],
                fuzz_message="subscriber_imsi_mismatch",
                description="Create subscriber then PUT with mismatched IMSI in path "
                            "vs body — audit log falsification (GHSA-xw45)",
                relevant_fields=["imsi"],
            ),
            # ── Backup / restore (GHSA-87j9) ─────────────────────────────────
            FuzzScenario(
                name="backup_then_restore_crafted",
                target_api="backup",
                setup_messages=["backup_get"],
                fuzz_message="restore_crafted",
                description="Download backup then POST crafted SQLite to /api/v1/restore "
                            "— arbitrary DB restore (GHSA-87j9)",
                relevant_fields=[],
            ),
            # ── Operator config ───────────────────────────────────────────────
            FuzzScenario(
                name="operator_nas_security_update",
                target_api="operator_write",
                setup_messages=["operator_get"],
                fuzz_message="operator_nas_update",
                description="Fetch operator config then mutate NAS security algorithms",
                relevant_fields=["var5qi", "sst"],
            ),
            # ── Credential exposure ───────────────────────────────────────────
            FuzzScenario(
                name="credentials_after_create",
                target_api="subscriber_read",
                setup_messages=["subscriber_create"],
                fuzz_message="subscriber_credentials",
                description="Create subscriber then GET /credentials — key material exposure",
                relevant_fields=["imsi"],
            ),
            # ── User CRUD ─────────────────────────────────────────────────────
            FuzzScenario(
                name="create_then_delete_user",
                target_api="user_write",
                setup_messages=["user_create"],
                fuzz_message="user_delete",
                description="Create fuzz user then DELETE — user management path",
                relevant_fields=[],
            ),
            FuzzScenario(
                name="create_user_then_update_role",
                target_api="user_write",
                setup_messages=["user_create"],
                fuzz_message="user_update",
                description="Create fuzz user then PUT with mutated roleId — privilege escalation probe",
                relevant_fields=["var5qi"],
            ),
            # ── BGP peer lifecycle ────────────────────────────────────────────
            FuzzScenario(
                name="create_bgp_peer_then_delete",
                target_api="networking_write",
                setup_messages=["bgp_peer_create"],
                fuzz_message="bgp_peer_delete",
                description="Create BGP peer then DELETE — networking write path",
                relevant_fields=[],
            ),
            # ── Route lifecycle ───────────────────────────────────────────────
            FuzzScenario(
                name="create_route_then_delete",
                target_api="networking_write",
                setup_messages=["route_create"],
                fuzz_message="route_delete",
                description="Create route then DELETE — static route manipulation",
                relevant_fields=[],
            ),
            # ── Cluster join token lifecycle ──────────────────────────────────
            FuzzScenario(
                name="create_join_token_then_delete",
                target_api="cluster_write",
                setup_messages=["cluster_join_token_create"],
                fuzz_message="cluster_join_token_delete",
                description="Create cluster join token then DELETE — PKI token management",
                relevant_fields=[],
            ),
            # ── Audit log retention tamper ────────────────────────────────────
            FuzzScenario(
                name="audit_log_retention_tamper",
                target_api="audit_write",
                setup_messages=["audit_logs_retention_get"],
                fuzz_message="audit_logs_retention_set",
                description="Read then mutate audit log retention period — log tampering probe",
                relevant_fields=["var5qi"],
            ),
        ]

    # ── Episode cleanup ───────────────────────────────────────────────────────

    # All resource paths the fuzzer might have created during an episode.
    # Deleted at episode start so subscriber_create / policy_create etc. can
    # succeed again instead of returning 409 every step after the first.
    _FUZZ_RESOURCE_PATHS: List[str] = [
        f"/api/v1/subscribers/{_VALID_IMSI}",
        "/api/v1/subscribers/001010000000001",  # _IMSI_VALUES[1]
        f"/api/v1/policies/{_VALID_POLICY}",
        f"/api/v1/slices/{_VALID_SLICE}",
        f"/api/v1/profiles/{_VALID_PROF}",
        "/api/v1/networking/data-networks/fuzz-dn",
        f"/api/v1/users/{_FUZZ_USER_EMAIL}",
        f"/api/v1/networking/routes/{_FUZZ_ROUTE_ID}",
        f"/api/v1/networking/bgp/peers/{_FUZZ_BGP_PEER_IP}",
        f"/api/v1/cluster/pki/join-tokens/{_FUZZ_JOIN_TOKEN_ID}",
    ]

    def _cleanup_fuzz_resources(self) -> None:
        """DELETE all known fuzz resources so the next episode starts with a clean slate."""
        if not self._target_host or not self._api_token:
            return
        import socket as _sock, ssl as _ssl
        host, port = self._target_host, self._target_port
        authority = f"{host}:{port}"
        for path in self._FUZZ_RESOURCE_PATHS:
            try:
                s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                s.setsockopt(_sock.IPPROTO_TCP, _sock.TCP_NODELAY, 1)
                s.settimeout(3.0)
                s.connect((host, port))
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = _ssl.CERT_NONE
                ctx.set_alpn_protocols(["h2"])
                s = ctx.wrap_socket(s, server_hostname=host)
                s.sendall(_build_request("DELETE", path, authority, auth=self._api_token))
                recv_h2_response(s, timeout=3.0)
                s.close()
            except Exception:
                pass  # 404 = never created this episode; connection errors = ignore

    # ── JWT refresh ───────────────────────────────────────────────────────────

    def _parse_token_exp(self, token: str) -> float:
        """Decode the exp claim from a JWT without verifying the signature."""
        try:
            import base64 as _b64
            raw = token.removeprefix("Bearer ").removeprefix("bearer ")
            payload_b64 = raw.split(".")[1]
            padding = (4 - len(payload_b64) % 4) % 4
            claims = json.loads(_b64.urlsafe_b64decode(payload_b64 + "=" * padding))
            return float(claims.get("exp", 0))
        except Exception:
            return 0.0

    def _do_login(self, host: str, port: int) -> None:
        """Login as the fuzz user and store a fresh JWT in self._api_token."""
        try:
            import socket as _sock, ssl as _ssl
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.setsockopt(_sock.IPPROTO_TCP, _sock.TCP_NODELAY, 1)
            s.settimeout(5.0)
            s.connect((host, port))
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = _ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2"])
            s = ctx.wrap_socket(s, server_hostname=host)

            authority = f"{host}:{port}"
            body = json.dumps({"email": self._FUZZ_EMAIL,
                               "password": self._FUZZ_PASSWORD}).encode()
            req = _build_request("POST", "/api/v1/auth/login",
                                 authority, body, "application/json", auth=None)
            s.sendall(req)
            resp_data = recv_h2_response(s, timeout=5.0)
            s.close()

            parsed = _parse_h2(resp_data)
            obj    = json.loads(parsed.get("body", b"{}"))
            # v1.11.0: {"result":{"token":"..."}}   v1.10.0: {"token":"..."}
            token = obj.get("token") or (obj.get("result") or {}).get("token", "")
            if token:
                self._api_token = f"Bearer {token}"
                self._token_exp = self._parse_token_exp(self._api_token)
                self._login_fail_count = 0
                logger.info("JWT obtained, exp=%s", int(self._token_exp))
            else:
                self._login_fail_count += 1
                self._login_retry_after = time.time() + 30
                if self._login_fail_count >= 3:
                    logger.warning("Login attempt %d failed (no token in response): %s",
                                   self._login_fail_count, obj)
                else:
                    logger.debug("Login: no token in response, will retry in 30s: %s", obj)
        except Exception as exc:
            self._login_fail_count += 1
            self._login_retry_after = time.time() + 30
            if self._login_fail_count >= 3:
                logger.warning("Login attempt %d failed (exception), will retry in 30s: %s",
                               self._login_fail_count, exc)
            else:
                logger.debug("Login transient failure, will retry in 30s: %s", exc)

    def notify_server_restarted(self) -> None:
        """Called by generic_env after a crash-triggered server restart.

        Ella rotates its JWT signing secret on every startup, so any token
        from before the restart is now invalid.  Reset the auth state so the
        next build_message() call forces a fresh login immediately (bypassing
        both the normal expiry window and the backoff timer).
        """
        logger.info("Server restarted — forcing fresh login on next request")
        self._initial_login_done = False
        self._login_retry_after  = 0.0
        self._login_fail_count   = 0
        # Keep self._api_token so we can still attempt a single fallback request
        # if the login unexpectedly fails again.

    def _refresh_token_if_needed(self, host: str, port: int) -> None:
        """Ensure self._api_token is valid.

        On the very first call we always login fresh — ella rotates its JWT
        signing secret during startup, so any token obtained via --api-token
        or get-token before initialisation completes is already invalid.
        Subsequently we re-login only when the token is within 5 minutes of
        expiry.
        """
        # Skip if this adapter was instantiated without auth intent
        if not self._api_token and self._initial_login_done:
            return

        if not self._initial_login_done:
            self._initial_login_done = True
            self._do_login(host, port)
            return

        # Honour backoff after a failed login attempt
        if time.time() < self._login_retry_after:
            return

        # Normal periodic refresh
        if self._token_exp == 0.0:
            self._token_exp = self._parse_token_exp(self._api_token)
        if time.time() < self._token_exp - 300:
            return
        logger.info("JWT expiring (exp=%s), refreshing…", int(self._token_exp))
        self._do_login(host, port)

    # ── Message building ──────────────────────────────────────────────────────

    def build_message(self, message_type: str, fields: Dict[str, Any],
                      payloads: Dict[str, bytes]) -> bytes:
        self._last_message_type = message_type

        # Refresh the JWT before it expires so long campaigns stay authenticated
        host = str(fields.get("_host", "localhost"))
        port = int(fields.get("_port", self.default_port))
        if not self._target_host:
            self._target_host = host
            self._target_port = port
        self._refresh_token_if_needed(host, port)

        imsi   = str(fields.get("imsi",         _VALID_IMSI))
        key    = str(fields.get("key",          _VALID_KEY))
        tac    = fields.get("tac",          1)
        sst    = fields.get("sst",          1)
        # Always use self._api_token (refreshed above), not fields["auth_mode"].
        # get_baseline_fields() is called before build_message so fields["auth_mode"]
        # carries the token from the PREVIOUS step — stale after any rotation/expiry.
        auth   = self._api_token
        ctype  = str(fields.get("content_type", "application/json"))
        method = str(fields.get("http_method",  "GET"))

        # Allow full body override from payload injection
        raw_body: Optional[bytes] = payloads.get("json_body")
        if payloads.get("imsi_field"):
            imsi = payloads["imsi_field"].decode("latin-1", errors="replace")

        authority = f"{fields.get('_host', 'localhost')}:{fields.get('_port', 5002)}"

        # ── Subscriber CRUD ───────────────────────────────────────────────────
        if message_type == "subscriber_create":
            body = raw_body or _subscriber_body(imsi=imsi, key=key)
            return _build_request("POST", "/api/v1/subscribers",
                                  authority, body, ctype, auth)

        if message_type == "subscriber_update":
            body = raw_body or _subscriber_body(imsi=imsi, key=key)
            path = f"/api/v1/subscribers/{imsi}"
            return _build_request("PUT", path, authority, body, ctype, auth)

        if message_type == "subscriber_delete":
            return _build_request("DELETE", f"/api/v1/subscribers/{imsi}",
                                  authority, auth=auth)

        if message_type == "subscriber_get":
            return _build_request("GET", f"/api/v1/subscribers/{imsi}",
                                  authority, auth=auth)

        if message_type == "subscriber_list":
            return _build_request("GET", "/api/v1/subscribers",
                                  authority, auth=auth)

        # ── Network slice CRUD  (/api/v1/slices) ─────────────────────────────
        if message_type == "slice_create":
            body = raw_body or _slice_body(sst=sst)
            return _build_request("POST", "/api/v1/slices",
                                  authority, body, ctype, auth)

        if message_type == "slice_update":
            body = raw_body or _slice_body(name=_VALID_SLICE, sst=sst)
            return _build_request("PUT", f"/api/v1/slices/{_VALID_SLICE}",
                                  authority, body, ctype, auth)

        if message_type == "slice_delete":
            return _build_request("DELETE", f"/api/v1/slices/{_VALID_SLICE}",
                                  authority, auth=auth)

        if message_type == "slice_list":
            return _build_request("GET", "/api/v1/slices",
                                  authority, auth=auth)

        # ── Policy CRUD  (/api/v1/policies) ──────────────────────────────────
        # ella has no REST API to create radios (gNBs auto-register via NGAP).
        # Policy CRUD replaces the former radio write operations.
        var5qi = fields.get("var5qi", 9)
        if message_type == "policy_create":
            body = raw_body or _policy_body(var5qi=var5qi)
            return _build_request("POST", "/api/v1/policies",
                                  authority, body, ctype, auth)

        if message_type == "policy_update":
            body = raw_body or _policy_body(name=_VALID_POLICY, var5qi=var5qi)
            return _build_request("PUT", f"/api/v1/policies/{_VALID_POLICY}",
                                  authority, body, ctype, auth)

        if message_type == "policy_delete":
            return _build_request("DELETE", f"/api/v1/policies/{_VALID_POLICY}",
                                  authority, auth=auth)

        if message_type == "policy_list":
            return _build_request("GET", "/api/v1/policies",
                                  authority, auth=auth)

        # ── Radio list (read-only — gNBs auto-register via NGAP) ─────────────
        if message_type == "radio_list":
            return _build_request("GET", "/api/v1/ran/radios",
                                  authority, auth=auth)

        # ── Profile CRUD  (/api/v1/profiles) ─────────────────────────────────
        if message_type == "profile_create":
            body = raw_body or _profile_body()
            return _build_request("POST", "/api/v1/profiles",
                                  authority, body, ctype, auth)

        if message_type == "profile_list":
            return _build_request("GET", "/api/v1/profiles",
                                  authority, auth=auth)

        # ── Attack messages ───────────────────────────────────────────────────
        if message_type == "path_traversal":
            import random as _r
            variants = [
                # IMSI-level directory traversal (existing)
                f"/api/v1/subscribers/../../../etc/passwd",
                f"/api/v1/subscribers/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                f"/api/v1/subscribers/..%00/etc/passwd",
                f"/api/v1/subscribers/{_VALID_IMSI}/../network-slices",
                f"/api/v1/subscribers/../../../../var/snap/ella-core/common/data/ella.db",
                # Path normalization / gRPC route bypass (#1129 — missing leading slash)
                "//api/v1/subscribers",          # double leading slash
                "/api/v1/subscribers/",          # trailing slash normalization
                "/api/v1/./subscribers",         # dot segment in path
                "/api/v1/subscribers%2f",        # URL-encoded trailing slash
                "/%61pi/v1/subscribers",         # first segment URL-encoded ('a' → %61)
            ]
            return _build_request("GET", _r.choice(variants), authority, auth=auth)

        if message_type == "method_confusion":
            # Send unexpected method to the policy list endpoint
            return _build_request(method, "/api/v1/policies",
                                  authority, auth=auth)

        if message_type == "large_body":
            # 1 MB body — exercises parser size limits and memory allocation
            big = b'{"imsi":"' + b"0" * 1_000_000 + b'","key":"' + _VALID_KEY.encode() + b'"}'
            return _build_request("POST", "/api/v1/subscribers",
                                  authority, big, ctype, auth)

        if message_type == "empty_body_post":
            # POST with empty body — nil body dereference probe
            return _build_request("POST", "/api/v1/subscribers",
                                  authority, b"", ctype, auth)

        if message_type == "type_confusion":
            # JSON array instead of object — Go json.Unmarshal into struct panics?
            body = raw_body or b'[{"imsi":"001010123456789"}]'
            return _build_request("POST", "/api/v1/subscribers",
                                  authority, body, ctype, auth)

        if message_type == "deep_nesting":
            # Deeply nested JSON — stack overflow in recursive decoder
            depth = 500
            body = (b'{"a":' * depth) + b'{}' + (b'}' * depth)
            return _build_request("POST", "/api/v1/subscribers",
                                  authority, body, ctype, auth)

        if message_type == "status_get":
            return _build_request("GET", "/api/v1/status",
                                  authority, auth=auth)

        # ── Auth endpoints ────────────────────────────────────────────────────

        if message_type == "auth_login":
            email    = fields.get("email",    "fuzz@test.com")
            password = fields.get("password", "password123")
            body = json.dumps({"email": email, "password": password}).encode()
            return _build_request("POST", "/api/v1/auth/login",
                                  authority, body, ctype, auth=None)  # intentionally no token

        if message_type == "auth_lookup_token":
            # Auth header carries the VALID JWT so the request reaches the handler.
            # Body token is the fuzz target — exercises the lookup endpoint's JWT
            # parsing code for unsafe type assertions (#1152) and claim confusion.
            import random as _r
            _jwt_body_probes = [
                "eyJ.",                                           # truncated header only
                "eyJhbGciOiJSUzI1NiJ9.",                         # RS256 alg, empty payload
                "eyJhbGciOiJub25lIn0.e30.",                      # alg:none signed token
                "eyJhbGciOiJIUzI1NiJ9." + "A" * 500 + ".",      # oversized payload segment
                "not.a.jwt",                                      # 3-part but non-base64
                "a.b.c.d.e",                                      # 5-part (non-standard count)
                "",                                               # empty token
                "null",                                           # JSON null literal
                # id claim type confusion: int where string expected (triggers type assertion
                # panic if the handler does claims["id"].(string) without nil check — #1152)
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MH0.",
                # id claim is null — nil interface assertion panic
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6bnVsbH0.",
            ]
            body = json.dumps({"token": _r.choice(_jwt_body_probes)}).encode()
            return _build_request("POST", "/api/v1/auth/lookup-token",
                                  authority, body, ctype, auth)

        # ── Subscriber sub-resources ──────────────────────────────────────────

        if message_type == "subscriber_credentials":
            # GET /api/v1/subscribers/{imsi}/credentials — exposes key material
            return _build_request("GET", f"/api/v1/subscribers/{imsi}/credentials",
                                  authority, auth=auth)

        if message_type == "subscriber_imsi_mismatch":
            # GHSA-xw45: PUT path IMSI ≠ body IMSI → audit log falsification
            # Path uses a DIFFERENT IMSI than the body; ella ≥1.8.0 should reject this.
            alt_imsi = "001010999999999"
            body = _subscriber_body(imsi=imsi)  # body has _VALID_IMSI
            return _build_request("PUT", f"/api/v1/subscribers/{alt_imsi}",
                                  authority, body, ctype, auth)

        # ── Backup/restore (GHSA-87j9) ────────────────────────────────────────

        if message_type == "backup_get":
            # Download the full database — may expose sensitive config
            return _build_request("GET", "/api/v1/backup", authority, auth=auth)

        if message_type == "restore_crafted":
            # POST a crafted/invalid SQLite to the restore endpoint.
            # GHSA-87j9 (fixed 1.7.0): no content validation; still worth testing.
            import random as _rng
            variants = [
                _SQLITE_MINIMAL,           # minimal valid SQLite
                _SQLITE_CRAFTED_HEADER,    # header with invalid page size
                b"Not a SQLite file",      # completely invalid
                b"",                       # empty body
                b"\x00" * 1024,            # all-null bytes
            ]
            body = _rng.choice(variants)
            return _build_request("POST", "/api/v1/restore",
                                  authority, body, "application/octet-stream", auth)

        # ── Operator config ───────────────────────────────────────────────────

        if message_type == "operator_get":
            return _build_request("GET", "/api/v1/operator", authority, auth=auth)

        if message_type == "operator_nas_update":
            # Mutate NAS security algorithm preferences — crypto config change
            body = json.dumps({
                "integrity_protection_algorithm": fields.get("var5qi", 1),
                "ciphering_algorithm": fields.get("sst", 0),
            }).encode()
            return _build_request("PUT", "/api/v1/operator/nas-security",
                                  authority, body, ctype, auth)

        # ── Debug / info-disclosure ───────────────────────────────────────────

        if message_type == "pprof_get":
            # Go pprof endpoint — should require admin auth; test for unauth access
            return _build_request("GET", "/api/v1/pprof/goroutine",
                                  authority, auth=auth)

        if message_type == "support_bundle_get":
            # Full support bundle download — may contain secrets, logs, config
            return _build_request("GET", "/api/v1/support-bundle",
                                  authority, auth=auth)

        # ── Data networks ─────────────────────────────────────────────────────

        if message_type == "data_network_list":
            return _build_request("GET", "/api/v1/networking/data-networks",
                                  authority, auth=auth)

        if message_type == "data_network_create":
            body = json.dumps({
                "name": "fuzz-dn",
                "ipv4_pool": "10.99.0.0/24",   # v1.11.0: renamed from "pool"
                "ipv6_pool": "",                 # v1.11.0: optional IPv6 pool
                "dns": "8.8.8.8",               # v1.11.0: renamed from "dns_primary"
                "mtu": fields.get("var5qi", 1500),
            }).encode()
            return _build_request("POST", "/api/v1/networking/data-networks",
                                  authority, body, ctype, auth)

        if message_type == "data_network_update":
            body = json.dumps({
                "name": "fuzz-dn",
                "ipv4_pool": "10.99.1.0/24",
                "ipv6_pool": "",
                "dns": "8.8.4.4",
                "mtu": 1400,
            }).encode()
            return _build_request("PUT", "/api/v1/networking/data-networks/fuzz-dn",
                                  authority, body, ctype, auth)

        if message_type == "data_network_delete":
            return _build_request("DELETE", "/api/v1/networking/data-networks/fuzz-dn",
                                  authority, auth=auth)

        # ── Auth extended ─────────────────────────────────────────────────────

        if message_type == "auth_refresh":
            body = json.dumps({"token": self._api_token.removeprefix("Bearer ") if self._api_token else ""}).encode()
            return _build_request("POST", "/api/v1/auth/refresh",
                                  authority, body, ctype, auth)

        if message_type == "auth_logout":
            return _build_request("POST", "/api/v1/auth/logout",
                                  authority, b"{}", ctype, auth)

        if message_type == "auth_rotate_secret":
            # Rotates the JWT signing secret — all existing tokens become invalid.
            # Intentionally low reward weight in compute_reward to avoid 401 cascade.
            return _build_request("POST", "/api/v1/auth/rotate-secret",
                                  authority, b"{}", ctype, auth)

        # ── Users CRUD + API tokens ───────────────────────────────────────────

        if message_type == "user_list":
            return _build_request("GET", "/api/v1/users", authority, auth=auth)

        if message_type == "user_create":
            body = raw_body or _user_body()
            return _build_request("POST", "/api/v1/users",
                                  authority, body, ctype, auth)

        if message_type == "user_get":
            email_enc = _url_quote(_FUZZ_USER_EMAIL, safe="@")
            return _build_request("GET", f"/api/v1/users/{email_enc}",
                                  authority, auth=auth)

        if message_type == "user_update":
            body = raw_body or json.dumps({"roleId": fields.get("var5qi", 1)}).encode()
            email_enc = _url_quote(_FUZZ_USER_EMAIL, safe="@")
            return _build_request("PUT", f"/api/v1/users/{email_enc}",
                                  authority, body, ctype, auth)

        if message_type == "user_delete":
            email_enc = _url_quote(_FUZZ_USER_EMAIL, safe="@")
            return _build_request("DELETE", f"/api/v1/users/{email_enc}",
                                  authority, auth=auth)

        if message_type == "user_password_update":
            body = json.dumps({"password": "NewPassword1!", "currentPassword": "Password1!"}).encode()
            email_enc = _url_quote(_FUZZ_USER_EMAIL, safe="@")
            return _build_request("PUT", f"/api/v1/users/{email_enc}/password",
                                  authority, body, ctype, auth)

        if message_type == "user_me_get":
            return _build_request("GET", "/api/v1/users/me", authority, auth=auth)

        if message_type == "user_me_password":
            body = json.dumps({"password": "NewPassword1!", "currentPassword": "password123"}).encode()
            return _build_request("PUT", "/api/v1/users/me/password",
                                  authority, body, ctype, auth)

        if message_type == "user_me_tokens_list":
            return _build_request("GET", "/api/v1/users/me/api-tokens", authority, auth=auth)

        if message_type == "user_me_token_create":
            body = json.dumps({"name": "fuzz-api-token"}).encode()
            return _build_request("POST", "/api/v1/users/me/api-tokens",
                                  authority, body, ctype, auth)

        if message_type == "user_me_token_delete":
            return _build_request("DELETE", f"/api/v1/users/me/api-tokens/{_FUZZ_JOIN_TOKEN_ID}",
                                  authority, auth=auth)

        # ── Init ─────────────────────────────────────────────────────────────

        if message_type == "init_post":
            # POST /api/v1/init — should return 409 on already-initialized instance.
            # Probes for logic that allows re-initialization and privilege escalation.
            body = json.dumps({
                "email": "init-fuzz@test.com", "password": "Password1!",
            }).encode()
            return _build_request("POST", "/api/v1/init",
                                  authority, body, ctype, auth=None)

        # ── Subscriber usage ──────────────────────────────────────────────────

        if message_type == "subscriber_usage_get":
            return _build_request("GET", "/api/v1/subscriber-usage", authority, auth=auth)

        if message_type == "subscriber_usage_delete":
            return _build_request("DELETE", "/api/v1/subscriber-usage", authority, auth=auth)

        if message_type == "subscriber_usage_retention_get":
            return _build_request("GET", "/api/v1/subscriber-usage/retention",
                                  authority, auth=auth)

        if message_type == "subscriber_usage_retention_set":
            body = raw_body or _retention_body(fields.get("var5qi", 30))
            return _build_request("PUT", "/api/v1/subscriber-usage/retention",
                                  authority, body, ctype, auth)

        # ── Profile get / update / delete ─────────────────────────────────────

        if message_type == "profile_get":
            return _build_request("GET", f"/api/v1/profiles/{_VALID_PROF}",
                                  authority, auth=auth)

        if message_type == "profile_update":
            body = raw_body or _profile_body(name=_VALID_PROF)
            return _build_request("PUT", f"/api/v1/profiles/{_VALID_PROF}",
                                  authority, body, ctype, auth)

        if message_type == "profile_delete":
            return _build_request("DELETE", f"/api/v1/profiles/{_VALID_PROF}",
                                  authority, auth=auth)

        # ── Operator full update ──────────────────────────────────────────────

        if message_type == "operator_update":
            body = raw_body or _operator_body()
            return _build_request("PUT", "/api/v1/operator",
                                  authority, body, ctype, auth)

        # ── Networking — routes ───────────────────────────────────────────────

        if message_type == "route_list":
            return _build_request("GET", "/api/v1/networking/routes", authority, auth=auth)

        if message_type == "route_create":
            body = raw_body or _route_body()
            return _build_request("POST", "/api/v1/networking/routes",
                                  authority, body, ctype, auth)

        if message_type == "route_delete":
            return _build_request("DELETE", f"/api/v1/networking/routes/{_FUZZ_ROUTE_ID}",
                                  authority, auth=auth)

        # ── Networking — BGP ──────────────────────────────────────────────────

        if message_type == "bgp_list":
            return _build_request("GET", "/api/v1/networking/bgp", authority, auth=auth)

        if message_type == "bgp_peer_create":
            body = raw_body or _bgp_peer_body()
            return _build_request("POST", "/api/v1/networking/bgp/peers",
                                  authority, body, ctype, auth)

        if message_type == "bgp_peer_update":
            body = raw_body or _bgp_peer_body(asn=fields.get("var5qi", 65001))
            return _build_request("PUT", f"/api/v1/networking/bgp/peers/{_FUZZ_BGP_PEER_IP}",
                                  authority, body, ctype, auth)

        if message_type == "bgp_peer_delete":
            return _build_request("DELETE", f"/api/v1/networking/bgp/peers/{_FUZZ_BGP_PEER_IP}",
                                  authority, auth=auth)

        if message_type == "bgp_advertised_routes":
            return _build_request("GET", "/api/v1/networking/bgp/advertised-routes",
                                  authority, auth=auth)

        if message_type == "bgp_learned_routes":
            return _build_request("GET", "/api/v1/networking/bgp/learned-routes",
                                  authority, auth=auth)

        # ── Networking — NAT / flow-accounting / interfaces / N3 ─────────────

        if message_type == "nat_get":
            return _build_request("GET", "/api/v1/networking/nat", authority, auth=auth)

        if message_type == "nat_update":
            body = raw_body or _nat_body()
            return _build_request("PUT", "/api/v1/networking/nat",
                                  authority, body, ctype, auth)

        if message_type == "flow_accounting_get":
            return _build_request("GET", "/api/v1/networking/flow-accounting",
                                  authority, auth=auth)

        if message_type == "flow_accounting_update":
            body = raw_body or _flow_accounting_body()
            return _build_request("PUT", "/api/v1/networking/flow-accounting",
                                  authority, body, ctype, auth)

        if message_type == "interfaces_list":
            return _build_request("GET", "/api/v1/networking/interfaces",
                                  authority, auth=auth)

        if message_type == "n3_get":
            return _build_request("GET", "/api/v1/networking/n3", authority, auth=auth)

        if message_type == "n3_update":
            body = raw_body or _n3_body()
            return _build_request("PUT", "/api/v1/networking/n3",
                                  authority, body, ctype, auth)

        # ── RAN events ────────────────────────────────────────────────────────

        if message_type == "ran_events_list":
            return _build_request("GET", "/api/v1/ran/events", authority, auth=auth)

        if message_type == "ran_events_delete":
            return _build_request("DELETE", "/api/v1/ran/events", authority, auth=auth)

        if message_type == "ran_events_retention_get":
            return _build_request("GET", "/api/v1/ran/events/retention",
                                  authority, auth=auth)

        if message_type == "ran_events_retention_set":
            body = raw_body or _retention_body(fields.get("var5qi", 30))
            return _build_request("PUT", "/api/v1/ran/events/retention",
                                  authority, body, ctype, auth)

        if message_type == "radio_get":
            return _build_request("GET", "/api/v1/ran/radios/gnb-fuzz",
                                  authority, auth=auth)

        # ── Flow reports ──────────────────────────────────────────────────────

        if message_type == "flow_reports_list":
            return _build_request("GET", "/api/v1/flow-reports", authority, auth=auth)

        if message_type == "flow_reports_delete":
            return _build_request("DELETE", "/api/v1/flow-reports", authority, auth=auth)

        if message_type == "flow_stats_get":
            return _build_request("GET", "/api/v1/flow-reports/stats", authority, auth=auth)

        if message_type == "flow_reports_retention_get":
            return _build_request("GET", "/api/v1/flow-reports/retention",
                                  authority, auth=auth)

        if message_type == "flow_reports_retention_set":
            body = raw_body or _retention_body(fields.get("var5qi", 30))
            return _build_request("PUT", "/api/v1/flow-reports/retention",
                                  authority, body, ctype, auth)

        # ── Audit logs ────────────────────────────────────────────────────────

        if message_type == "audit_logs_list":
            return _build_request("GET", "/api/v1/audit-logs", authority, auth=auth)

        if message_type == "audit_logs_retention_get":
            return _build_request("GET", "/api/v1/audit-logs/retention",
                                  authority, auth=auth)

        if message_type == "audit_logs_retention_set":
            body = raw_body or _retention_body(fields.get("var5qi", 30))
            return _build_request("PUT", "/api/v1/audit-logs/retention",
                                  authority, body, ctype, auth)

        # ── Metrics ───────────────────────────────────────────────────────────

        if message_type == "metrics_get":
            return _build_request("GET", "/api/v1/metrics", authority, auth=auth)

        # ── Cluster ───────────────────────────────────────────────────────────

        if message_type == "cluster_members_list":
            return _build_request("GET", "/api/v1/cluster/members", authority, auth=auth)

        if message_type == "cluster_member_delete":
            return _build_request("DELETE", f"/api/v1/cluster/members/{_FUZZ_CLUSTER_MEMBER}",
                                  authority, auth=auth)

        if message_type == "cluster_member_promote":
            return _build_request("POST",
                                  f"/api/v1/cluster/members/{_FUZZ_CLUSTER_MEMBER}/promote",
                                  authority, b"{}", ctype, auth)

        if message_type == "cluster_member_drain":
            return _build_request("POST",
                                  f"/api/v1/cluster/members/{_FUZZ_CLUSTER_MEMBER}/drain",
                                  authority, b"{}", ctype, auth)

        if message_type == "cluster_member_resume":
            return _build_request("POST",
                                  f"/api/v1/cluster/members/{_FUZZ_CLUSTER_MEMBER}/resume",
                                  authority, b"{}", ctype, auth)

        if message_type == "cluster_autopilot_get":
            return _build_request("GET", "/api/v1/cluster/autopilot", authority, auth=auth)

        if message_type == "cluster_join_tokens_list":
            return _build_request("GET", "/api/v1/cluster/pki/join-tokens",
                                  authority, auth=auth)

        if message_type == "cluster_join_token_create":
            body = json.dumps({"name": _FUZZ_JOIN_TOKEN_ID}).encode()
            return _build_request("POST", "/api/v1/cluster/pki/join-tokens",
                                  authority, body, ctype, auth)

        if message_type == "cluster_join_token_delete":
            return _build_request("DELETE",
                                  f"/api/v1/cluster/pki/join-tokens/{_FUZZ_JOIN_TOKEN_ID}",
                                  authority, auth=auth)

        # ── Pprof sub-endpoints ───────────────────────────────────────────────

        if message_type == "pprof_heap":
            return _build_request("GET", "/api/v1/pprof/heap", authority, auth=auth)

        if message_type == "pprof_profile":
            return _build_request("GET", "/api/v1/pprof/profile?seconds=1",
                                  authority, auth=auth)

        if message_type == "pprof_trace":
            return _build_request("GET", "/api/v1/pprof/trace?seconds=1",
                                  authority, auth=auth)

        # Fallback
        logger.warning("Unknown message_type=%s, sending status probe", message_type)
        return _build_request("GET", "/api/v1/status", authority)

    # ── Response parsing ──────────────────────────────────────────────────────

    def parse_response(self, data: bytes) -> Dict[str, Any]:
        if not data:
            return {"type": "closed", "success": False, "status": None}

        parsed = _parse_h2(data)
        status = parsed.get("status")

        if status is None:
            if parsed.get("goaway"):
                return {"type": "goaway", "success": False, "status": None,
                        "h2_error": parsed.get("h2_error", 0)}
            return {"type": "empty", "success": False, "status": None}

        # Classify by HTTP status
        if status < 300:
            rtype = f"http_{status}"
        elif status < 400:
            rtype = f"http_{status}"
        elif status == 400:
            rtype = "bad_request"
        elif status == 401:
            rtype = "unauthorized"
        elif status == 403:
            rtype = "forbidden"
        elif status == 404:
            rtype = "not_found"
        elif status == 405:
            rtype = "method_not_allowed"
        elif status == 409:
            rtype = "conflict"
        elif status == 413:
            rtype = "payload_too_large"
        elif status == 422:
            rtype = "unprocessable"
        elif status >= 500:
            rtype = f"server_error_{status}"
        else:
            rtype = f"http_{status}"

        # Parse body for error detail depth scoring.
        # v1.11.0 wraps success responses: {"result": {"message": "...", ...}}
        # Error responses remain flat:       {"error": "..."}
        body = parsed.get("body", b"")
        error_detail = ""
        body_depth = 0.0
        try:
            obj = json.loads(body)
            if isinstance(obj, dict):
                # Unwrap v1.11.0 result envelope if present
                inner = obj.get("result", obj)
                if isinstance(inner, dict):
                    error_detail = str(inner.get("error", inner.get("message", "")))
                else:
                    error_detail = str(obj.get("error", obj.get("message", "")))
                body_depth = _score_error_detail(error_detail)
        except Exception:
            pass

        return {
            "type":         rtype,
            "success":      200 <= status < 300,
            "status":       status,
            "error_detail": error_detail,
            "body_depth":   body_depth,
            "body_len":     len(body),
            "goaway":       parsed.get("goaway", False),
        }

    # ── Interesting response classification ───────────────────────────────────

    def is_interesting_response(self, response: Dict[str, Any]) -> Tuple[bool, float]:
        rtype = response.get("type", "")
        table = {
            # Server-side errors — highest value (bug in request handling)
            "server_error_500":   (True,  10.0),
            "server_error_502":   (True,   7.0),
            "server_error_503":   (True,   5.0),
            "server_error_504":   (True,   5.0),
            # Write successes — dqlite write path reached
            "http_201":           (True,   8.0),  # resource created
            "http_204":           (True,   5.0),  # delete success
            "http_200":           (True,   3.0),
            # Deep validation — handler processed the body before rejecting
            "unprocessable":      (True,   4.0),  # 422 — deepest input validation
            "conflict":           (True,   3.5),  # 409 — DB constraint hit
            "bad_request":        (True,   2.5),  # 400 — field-level rejection
            "payload_too_large":  (True,   2.0),  # 413
            "method_not_allowed": (True,   1.5),  # 405
            "forbidden":          (True,   1.0),  # 403 — auth layer, but deeper than 401
            # Shallow rejections — not useful signal
            "not_found":          (False,  0.2),  # 404 — routing miss
            "unauthorized":       (False,  0.0),  # 401 — auth check, shallowest possible
            # Transport anomalies
            "goaway":             (True,   3.0),
            "empty":              (True,   1.0),
            "closed":             (False,  0.0),
        }
        if rtype.startswith("server_error_"):
            return (True, 5.0)
        return table.get(rtype, (True, 1.5))  # unknown status = interesting

    # ── Message-type categories ───────────────────────────────────────────────

    _READ_MSG_TYPES = frozenset({
        "subscriber_list", "subscriber_get", "subscriber_credentials",
        "radio_list", "radio_get",
        "slice_list",
        "policy_list",
        "profile_list", "profile_get",
        "operator_get",
        "data_network_list",
        "backup_get", "pprof_get", "pprof_heap", "pprof_profile", "pprof_trace",
        "support_bundle_get",
        "status_get",
        "user_list", "user_get", "user_me_get", "user_me_tokens_list",
        "subscriber_usage_get", "subscriber_usage_retention_get",
        "route_list",
        "bgp_list", "bgp_advertised_routes", "bgp_learned_routes",
        "nat_get", "flow_accounting_get", "interfaces_list", "n3_get",
        "ran_events_list", "ran_events_retention_get",
        "flow_reports_list", "flow_stats_get", "flow_reports_retention_get",
        "audit_logs_list", "audit_logs_retention_get",
        "metrics_get",
        "cluster_members_list", "cluster_autopilot_get", "cluster_join_tokens_list",
    })

    _WRITE_MSG_TYPES = frozenset({
        "subscriber_create", "subscriber_update", "subscriber_delete",
        "subscriber_imsi_mismatch",
        "subscriber_usage_delete", "subscriber_usage_retention_set",
        "slice_create", "slice_update", "slice_delete",
        "policy_create", "policy_update", "policy_delete",
        "profile_create", "profile_update", "profile_delete",
        "operator_nas_update", "operator_update",
        "data_network_create", "data_network_update", "data_network_delete",
        "auth_login", "auth_lookup_token", "auth_refresh", "auth_logout", "auth_rotate_secret",
        "restore_crafted",
        "user_create", "user_update", "user_delete", "user_password_update",
        "user_me_password", "user_me_token_create", "user_me_token_delete",
        "init_post",
        "route_create", "route_delete",
        "bgp_peer_create", "bgp_peer_update", "bgp_peer_delete",
        "nat_update", "flow_accounting_update", "n3_update",
        "ran_events_delete", "ran_events_retention_set",
        "flow_reports_delete", "flow_reports_retention_set",
        "audit_logs_retention_set",
        "cluster_member_delete", "cluster_member_promote",
        "cluster_member_drain", "cluster_member_resume",
        "cluster_join_token_create", "cluster_join_token_delete",
    })

    # ── Reward computation ────────────────────────────────────────────────────

    def compute_reward(self, response: Dict[str, Any],
                       response_time_ms: float,
                       field_mutations: Dict[str, Any],
                       payload_injections: Dict[str, bytes],
                       **_kwargs) -> float:
        reward = 0.0
        rtype  = response.get("type", "")
        status = response.get("status")
        msg_type = self._last_message_type

        # Skip bonuses when connection was closed before processing
        if rtype == "closed":
            return -1.0

        is_interesting, mult = self.is_interesting_response(response)
        if is_interesting:
            reward += 20.0 * mult

        # Novelty bonus — first time this status code appears this episode
        if status and status not in self._episode_status_set:
            self._episode_status_set.add(status)
            reward += 10.0

        # Error body depth score — how far into ella's handler we got
        body_depth = response.get("body_depth", 0.0)
        if body_depth > 0:
            reward += body_depth * 35.0

        # Write-path bonus: reaching dqlite write is the primary campaign goal.
        # Success on a write operation gets a large bonus regardless of HTTP code.
        if msg_type in self._WRITE_MSG_TYPES:
            if response.get("success"):
                reward += 50.0  # write committed to dqlite
            elif rtype in ("bad_request", "unprocessable", "conflict"):
                reward += 20.0  # write handler reached, validation fired
            elif rtype == "not_found":
                reward += 10.0  # write routing reached

        # Penalise 307 redirects — wasted steps with no useful signal
        if rtype == "http_307":
            reward -= 3.0

        # Diminishing returns for read-only operations within an episode.
        # After 3 reads of the same message type the reward is halved each
        # additional hit, capping the incentive to camp on list/status calls.
        if msg_type in self._READ_MSG_TYPES:
            count = self._episode_read_counts.get(msg_type, 0)
            self._episode_read_counts[msg_type] = count + 1
            if count >= 3:
                decay = max(0.0, 1.0 - (count - 3) * 0.3)
                reward = reward * decay

        # Diminishing returns for write operations — prevents the agent from
        # camping on policy_create+var5qi which reliably yields 201 every step.
        # Softer than reads: threshold=5, 20% decay per extra hit.
        if msg_type in self._WRITE_MSG_TYPES:
            count = self._episode_write_counts.get(msg_type, 0)
            self._episode_write_counts[msg_type] = count + 1
            if count >= 5:
                decay = max(0.1, 1.0 - (count - 5) * 0.2)
                reward = reward * decay

        # Slow response — potential computation bottleneck or blocking call
        if response_time_ms > 500:
            reward += 30.0
        elif response_time_ms > 200:
            reward += 15.0

        # Field boundary bonus — only when server processed the request
        if status and status not in (401, 404):
            if field_mutations.get("var5qi") in {0, 255, 256, -1, 87, 2**31 - 1}:
                reward += 5.0
            if field_mutations.get("sst") in {0, 255, -1, 256}:
                reward += 5.0
            if field_mutations.get("imsi") in {"", "../../../etc/passwd",
                                                "'; DROP TABLE subscribers; --"}:
                reward += 8.0  # high-value attack reached the handler

        # Auth bypass: only award when auth_mode was EXPLICITLY set to None in
        # the action's field mutations (not merely absent from the dict).
        if (response.get("success")
                and "auth_mode" in field_mutations
                and field_mutations["auth_mode"] is None):
            reward += 25.0

        # High-value endpoint bonuses (security-critical surfaces)
        if msg_type == "restore_crafted" and response.get("success"):
            # Successful restore with crafted SQLite — priv-esc surface (GHSA-87j9)
            reward += 150.0
        if msg_type == "backup_get" and response.get("success"):
            # Backup download succeeded — sensitive data exposure
            reward += 40.0
        if msg_type == "pprof_get" and response.get("success"):
            # pprof accessible — should require admin auth; unauth = info disclosure
            reward += 30.0
        if msg_type == "support_bundle_get" and response.get("success"):
            reward += 50.0
        if msg_type == "subscriber_imsi_mismatch":
            if response.get("success"):
                # 2xx on IMSI mismatch = audit log falsification reproduced (GHSA-xw45)
                reward += 80.0
            elif rtype == "bad_request":
                # Correctly rejected — but handler was reached
                reward += 15.0
        if msg_type == "auth_login":
            if response.get("success"):
                reward += 60.0   # successful login — credential worked or SQLi bypass
            elif "email" in field_mutations and rtype != "unauthorized":
                reward += 8.0    # login handler reached with mutated email (SQLi probe)
            # 401 from wrong credentials = no bonus — prevents camping on login probes

        # auth_rotate_secret: penalise success — it invalidates all tokens and causes 401 cascade
        if msg_type == "auth_rotate_secret":
            if response.get("success"):
                reward -= 5.0   # force re-login but suppress the temptation to spam
            else:
                reward = max(reward, 2.0)  # handler reached is mildly interesting

        # User management: high value — creates/elevates accounts
        if msg_type == "user_create" and response.get("success"):
            reward += 40.0
        if msg_type == "user_update" and response.get("success"):
            reward += 30.0   # role escalation possible
        if msg_type == "user_delete" and response.get("success"):
            reward += 20.0

        # Init re-run: critical — successful re-init on live instance is a full reset
        if msg_type == "init_post":
            if response.get("success"):
                reward += 200.0
            elif rtype == "conflict":
                reward += 15.0   # correctly rejected (409)

        # Cluster membership changes: high-impact on availability
        if msg_type in ("cluster_member_promote", "cluster_member_drain", "cluster_member_delete"):
            if response.get("success"):
                reward += 80.0
            elif rtype not in ("not_found", "unauthorized"):
                reward += 10.0

        # Audit log retention update: tamper with evidence retention
        if msg_type == "audit_logs_retention_set" and response.get("success"):
            reward += 50.0

        # Operator update: changes core network identity (MCC/MNC)
        if msg_type == "operator_update" and response.get("success"):
            reward += 60.0

        # Unexpected 401 on an authenticated endpoint means the token is stale.
        # Mark it expired so the next build_message call re-logins.
        if rtype == "unauthorized" and msg_type not in ("auth_login", "auth_lookup_token"):
            self._token_exp = 0.0
            reward -= 2.0  # penalise wasting a step on a broken-auth request

        # Crash detection
        if self._monitor.detect_crash():
            reward += 200.0
        else:
            logs = self._monitor.recent_logs_by_level(30)
            if logs.get("fatal"):
                reward += 60.0
            score = self._monitor.anomaly_score()
            if score > 0:
                reward += score * 80.0

        self._last_response_type = rtype
        return reward

    # ── Health check ──────────────────────────────────────────────────────────

    def check_health(self, host: str, port: int,
                     timeout: float = 5.0) -> HealthCheckResult:
        """GET /api/v1/status → 200 means ella is up."""
        import socket, ssl
        result = HealthCheckResult(is_healthy=False, latency_ms=0.0)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(timeout)
            sock.connect((host, port))

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2"])
            sock = ctx.wrap_socket(sock, server_hostname=host)

            authority = f"{host}:{port}"
            req = _build_request("GET", "/api/v1/status", authority)
            t0 = time.monotonic()
            sock.sendall(req)
            resp_data = recv_h2_response(sock, timeout=timeout)
            latency = (time.monotonic() - t0) * 1000
            sock.close()

            parsed = self.parse_response(resp_data)
            status = parsed.get("status")
            result.is_healthy  = status == 200
            result.latency_ms  = latency
            result.details     = {"status": status, "type": parsed.get("type")}
        except Exception as e:
            result.error = str(e)
        return result

    def pre_request_snapshot(self) -> int:
        """Snapshot log file position before each request for anomaly scoring."""
        try:
            import os
            return os.path.getsize(self._log_path)
        except OSError:
            return 0

    # ── Observation encoding ──────────────────────────────────────────────────

    # Known response types (order matters — defines one-hot index)
    _RESP_TYPES = [
        "http_200", "http_201", "http_204", "http_307",
        "bad_request", "unauthorized", "not_found", "conflict",
        "unprocessable", "goaway", "empty", "closed", "server_error",
    ]
    # Known message types (order matters — defines one-hot index)
    _MSG_TYPES = [
        "subscriber_create", "subscriber_get", "subscriber_update",
        "subscriber_delete", "subscriber_list",
        "slice_create", "slice_update", "slice_delete", "slice_list",
        "policy_create", "policy_update", "policy_delete", "policy_list",
        "profile_create", "profile_list", "profile_get", "profile_update", "profile_delete",
        "radio_list", "radio_get", "status_get",
        # Auth endpoints
        "auth_login", "auth_lookup_token", "auth_refresh", "auth_logout", "auth_rotate_secret",
        # Subscriber sub-resources
        "subscriber_credentials", "subscriber_imsi_mismatch",
        "subscriber_usage_get", "subscriber_usage_delete",
        "subscriber_usage_retention_get", "subscriber_usage_retention_set",
        # Backup / restore
        "backup_get", "restore_crafted",
        # Operator config
        "operator_get", "operator_nas_update", "operator_update",
        # Debug / info-disclosure
        "pprof_get", "pprof_heap", "pprof_profile", "pprof_trace",
        "support_bundle_get",
        # Data networks
        "data_network_list", "data_network_create", "data_network_update", "data_network_delete",
        # Users CRUD + API tokens
        "user_list", "user_create", "user_get", "user_update", "user_delete",
        "user_password_update", "user_me_get", "user_me_password",
        "user_me_tokens_list", "user_me_token_create", "user_me_token_delete",
        # Init
        "init_post",
        # Networking — routes
        "route_list", "route_create", "route_delete",
        # Networking — BGP
        "bgp_list", "bgp_peer_create", "bgp_peer_update", "bgp_peer_delete",
        "bgp_advertised_routes", "bgp_learned_routes",
        # Networking — misc
        "nat_get", "nat_update",
        "flow_accounting_get", "flow_accounting_update",
        "interfaces_list", "n3_get", "n3_update",
        # RAN events
        "ran_events_list", "ran_events_delete",
        "ran_events_retention_get", "ran_events_retention_set",
        # Flow reports
        "flow_reports_list", "flow_reports_delete", "flow_stats_get",
        "flow_reports_retention_get", "flow_reports_retention_set",
        # Audit logs
        "audit_logs_list", "audit_logs_retention_get", "audit_logs_retention_set",
        # Metrics
        "metrics_get",
        # Cluster
        "cluster_members_list", "cluster_member_delete",
        "cluster_member_promote", "cluster_member_drain", "cluster_member_resume",
        "cluster_autopilot_get",
        "cluster_join_tokens_list", "cluster_join_token_create", "cluster_join_token_delete",
        # Generic attack messages
        "path_traversal", "method_confusion", "large_body",
        "empty_body_post", "type_confusion", "deep_nesting",
    ]

    def get_observation_size(self) -> int:
        # 13 response one-hot + N message one-hot + 9 scalars
        return len(self._RESP_TYPES) + len(self._MSG_TYPES) + 9

    def encode_observation(self, fields: Dict[str, Any],
                           response_history: List[str],
                           counters: Dict[str, int],
                           step: int, max_steps: int) -> List[float]:
        import numpy as np
        obs = np.zeros(self.get_observation_size(), dtype=np.float32)
        base = 0

        # [0:13] one-hot for last response type
        rtype = self._last_response_type
        if rtype in self._RESP_TYPES:
            obs[base + self._RESP_TYPES.index(rtype)] = 1.0
        elif rtype.startswith("server_error"):
            obs[base + self._RESP_TYPES.index("server_error")] = 1.0
        base += len(self._RESP_TYPES)

        # [13:31] one-hot for last message type
        mtype = self._last_message_type
        if mtype in self._MSG_TYPES:
            obs[base + self._MSG_TYPES.index(mtype)] = 1.0
        base += len(self._MSG_TYPES)

        # [31] step progress
        obs[base + 0] = step / max(max_steps, 1)
        # [32] write success rate this episode (201 responses seen)
        obs[base + 1] = min(counters.get("successes", 0) / 10.0, 1.0)
        # [33] crash count (normalized)
        obs[base + 2] = min(counters.get("crashes", 0) / 3.0, 1.0)
        # [34] unauthorized rate (noisy auth testing)
        obs[base + 3] = min(counters.get("errors", 0) / 10.0, 1.0)
        # [35] read saturation: how many read types are decaying
        saturated = sum(1 for v in self._episode_read_counts.values() if v >= 3)
        obs[base + 4] = min(saturated / 5.0, 1.0)
        # [36] write saturation: how many write types are decaying
        write_sat = sum(1 for v in self._episode_write_counts.values() if v >= 5)
        obs[base + 5] = min(write_sat / 5.0, 1.0)
        # [37] var5qi boundary active (agent mutated var5qi this step)
        obs[base + 6] = 1.0 if fields.get("var5qi") not in (9, None) else 0.0
        # [38] auth boundary active (agent testing auth bypass)
        obs[base + 7] = 1.0 if fields.get("auth_mode") is None else 0.0
        # [39] episode novelty: unique statuses seen (normalized)
        obs[base + 8] = min(len(self._episode_status_set) / 8.0, 1.0)

        return obs.tolist()

    def get_baseline_fields(self) -> Dict[str, Any]:
        return {
            "imsi":         _VALID_IMSI,
            "key":          _VALID_KEY,
            "var5qi":       9,
            "sst":          1,
            "content_type": "application/json",
            "http_method":  "POST",
        }


# ── Error body depth scorer ───────────────────────────────────────────────────

_DEPTH_KEYWORDS: List[Tuple[float, str]] = [
    # High-value: field-level validation reached deep in the handler
    (0.90, "imsi"),
    (0.88, "key"),
    (0.85, "opc"),
    (0.82, "tac"),
    (0.80, "sequence_number"),
    (0.78, "constraint"),
    (0.75, "foreign key"),
    (0.72, "unique"),
    (0.70, "invalid"),
    (0.65, "parse"),
    (0.60, "unmarshal"),
    (0.55, "required"),
    (0.50, "missing"),
    (0.45, "not found"),
    (0.40, "unauthorized"),
    (0.20, "error"),
]

def _score_error_detail(detail: str) -> float:
    """Score how deeply into ella's handler the request reached based on the error message."""
    if not detail:
        return 0.0
    lo = detail.lower()
    for score, kw in _DEPTH_KEYWORDS:
        if kw in lo:
            return score
    return 0.05
