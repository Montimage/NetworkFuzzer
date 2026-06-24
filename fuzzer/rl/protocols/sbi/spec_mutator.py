#!/usr/bin/env python3
"""
Spec-driven mutation generator for 5G SBI fuzzing.

Derives fuzzing inputs from EndpointSpec / FieldSchema dataclasses, combining:
  1. Schema-constraint mutations  — boundaries from minLength/maxLength/enum/…
  2. FivGeeFuzz attack classes    — bugs found in free5GC by omitting optional fields,
                                    type mismatches, and cross-service token reuse
  3. 5G-semantic mutations        — SUPI format variants, UUID edge cases, NSSAI,
                                    scope strings, access-token confusion
  4. open5GS / free5GC target-specific values from known CVE/issue analysis

All mutation lists are deterministic (no randomness) so they can be serialised
to spec_mutations.json and replayed exactly.

Public API:
    mutations_for_field(fs)                  → list of values for one field
    build_valid_body(ep, defaults)           → minimal valid request body
    build_missing_required(ep, defaults, f)  → body with one required field removed
    build_missing_optional(ep, defaults, f)  → body with one optional field removed (FivGeeFuzz)
    build_type_mismatch(ep, defaults, f)     → body with wrong type for one field
    fivgee_omit_optional_scenarios(ep)       → list of (field, body) for Bug 1/2/5 class
    fivgee_type_mismatch_scenarios(ep)       → list of (field, body) for Bug 3/6 class
    cross_service_token_payloads()           → list of scope confusion payloads
    producer_consumer_sequence(ep, registry) → ordered prerequisite operation IDs
"""

from __future__ import annotations

import copy
from typing import Any

from .spec_parser import EndpointSpec, FieldSchema

# ---------------------------------------------------------------------------
# 5G-semantic value pools
# These supplement the schema-derived boundary values with protocol-specific
# knowledge about 3GPP formats that the spec alone doesn't capture.
# ---------------------------------------------------------------------------

# SUPI — 3GPP TS 29.571 §5.4
_SUPI_POOL: list[Any] = [
    "imsi-001010000000001",              # valid open5GS default
    "imsi-208930000000001",              # valid free5GC default
    "imsi-001010000000002",              # second valid
    "imsi-000000000000000",              # all zeros — boundary
    "imsi-999999999999999",              # all nines — boundary
    "imsi-0",                            # too short
    "imsi-" + "1" * 30,                 # too long
    "imsi-",                             # prefix only, no digits (#4412 style)
    "imsi:",                             # wrong separator (colon instead of dash)
    "imsi-001010000000001\x00injected",  # null-byte injection
    "",                                  # empty — mandatory field missing
    None,                                # absent
    "suci-0-208-93-0-0-0-0000000001",   # valid SUCI
    "suci-0-208-93-0-0-0-",             # SUCI with empty scheme-output
    "suci-0-",                           # truncated SUCI
    "5g-guti-9990700000000000001",       # 5G-GUTI (triggers AMF context transfer)
    "A" * 256,                           # oversized
    "imsi-001010000000001%00",           # URL-encoded null
    "../admin",                           # path traversal
]

# UUID — RFC 4122
_UUID_POOL: list[Any] = [
    "11111111-1111-1111-1111-111111111111",   # valid fuzz UUID
    "00000000-0000-0000-0000-000000000000",   # all zeros
    "ffffffff-ffff-ffff-ffff-ffffffffffff",   # all f's
    "fake-smf-nrf",                           # non-UUID (open5GS #4469 smfInfo overflow)
    "fake-amf-nrf",                           # non-UUID (open5GS #4467 amfInfo overflow)
    "",                                        # empty
    "not-a-uuid",
    "11111111-1111-1111-1111",                # truncated
    "11111111-1111-1111-1111-1111111111111",  # one char too long
    "A" * 36,                                 # right length, wrong chars
    None,
]

# S-NSSAI — 3GPP TS 29.571
_SNSSAI_POOL: list[Any] = [
    {"sst": 1},                              # minimal valid (no SD)
    {"sst": 1, "sd": "010203"},             # full valid
    {"sst": 0},                              # invalid SST (reserved)
    {"sst": 255},                            # boundary
    {"sst": 256},                            # overflow
    {"sst": -1},                             # negative
    {"sst": 1, "sd": "FFFFFF"},             # no-SD sentinel
    {"sst": 1, "sd": ""},                    # empty SD
    {"sst": 1, "sd": "GGGGGG"},             # invalid hex SD
    {"sst": 1, "sd": "0" * 64},            # oversized SD
    {},                                       # empty object
    None,
]

# Scope strings — TS 29.510 §6.1 / RFC 8693
_SCOPE_POOL: list[Any] = [
    "nudm-sdm",       "nudm-uecm",    "nudm-ueau",    # UDM services
    "nudr-dr",                                          # UDR
    "nnrf-nfm",       "nnrf-disc",                     # NRF services
    "namf-comm",      "namf-evts",                     # AMF services
    "nsmf-pdusession","nsmf-nfm",                     # SMF services
    "nausf-auth",                                       # AUSF
    "npcf-am",        "npcf-smpolicycontrol",          # PCF services
    "nudr-dr nudm-sdm",                                # multi-scope (space-separated)
    "INVALID_SCOPE",                                    # unknown scope
    "",                                                  # empty scope
    None,
    "A" * 512,                                          # oversized
    # Cross-service confusion (FivGeeFuzz Bug 8): scope for NF-A sent to NF-B
    # Included here so the RL agent can learn this attack class
    ("nudm-sdm", "NRF"),      # UDM scope → NRF target
    ("nnrf-disc", "AMF"),      # NRF scope → AMF target
    ("nsmf-pdusession", "UDM"),# SMF scope → UDM target
]

# PLMN identifiers
_PLMN_MCC_POOL: list[Any] = ["001", "208", "999", "000", "", "9999", "ABC", None]
_PLMN_MNC_POOL: list[Any] = ["01", "93", "70", "001", "", "9999", "ZZ", None]

# DNN — Data Network Name
_DNN_POOL: list[Any] = [
    "internet", "ims", "internet2",
    "",
    "A" * 100,
    "\x00\x01\x02",
    None,
]

# Generic string pools by format
_FORMAT_POOLS: dict[str, list[Any]] = {
    "uuid":       _UUID_POOL,
    "supi":       _SUPI_POOL,
    "date-time":  [
        "2030-01-01T00:00:00Z",  # valid far future
        "2000-01-01T00:00:00Z",  # valid past
        "",                       # empty
        "not-a-date",
        "9999-99-99T99:99:99Z",  # invalid date
        None,
    ],
    "binary":     ["", "AA==", "AAAA", "A" * 1024, "\x00\xFF", None],
    "byte":       ["", "AA==", "dGVzdA==", "A" * 1024, None],
    "int32":      [0, 1, -1, 2**31 - 1, 2**31, -(2**31), None],
    "int64":      [0, 1, -1, 2**63 - 1, 2**63, -(2**63), None],
    "ipv4":       ["10.45.0.1", "127.0.0.1", "0.0.0.0", "255.255.255.255", "", "999.999.999.999", None],
    "ipv6":       ["::1", "fe80::1", "", "gggg::1", None],
    "uri":        ["http://127.0.0.1:7777/callback", "", "javascript:alert(1)", "http://" + "A" * 200, None],
}

# Type-mismatch injections — wrong type for a given schema type (FivGeeFuzz Bug 3/6)
_TYPE_MISMATCHES: dict[str, list[Any]] = {
    "string":  [0, True, [], {}, None],
    "integer": ["not-an-int", True, [], {}, None],
    "boolean": ["true", "false", 0, 1, None],
    "array":   ["not-an-array", 0, {}, None],
    "object":  ["not-an-object", 0, [], None],
    "number":  ["not-a-number", True, [], {}, None],
}


# ---------------------------------------------------------------------------
# Core mutation generator
# ---------------------------------------------------------------------------

def mutations_for_field(fs: FieldSchema) -> list[Any]:
    """
    Return a deduplicated list of mutation values for a single FieldSchema.

    Combines:
    - Schema constraint boundaries (min/max length, min/max value, enum)
    - Format-specific pools (UUID, SUPI, date-time, …)
    - Universal injections (null byte, empty, None for required fields)
    - FivGeeFuzz type mismatch values
    """
    vals: list[Any] = []

    # 1. Enum: include all valid values + one invalid
    if fs.enum:
        vals.extend(fs.enum)
        vals.append("")                   # not in enum
        vals.append(str(fs.enum[0]) * 2) # doubled value — wrong format
        vals.append("INVALID_ENUM_VALUE")

    # 2. Format-specific pool
    fmt = fs.format.lower() if fs.format else ""
    if fmt in _FORMAT_POOLS:
        vals.extend(_FORMAT_POOLS[fmt])
    elif "supi" in fs.name.lower() or "suci" in fs.name.lower():
        vals.extend(_SUPI_POOL)
    elif "uuid" in fs.name.lower() or fs.name.lower().endswith("id") and fmt == "":
        if fs.type == "string":
            vals.extend(_UUID_POOL)
    elif "snssai" in fs.name.lower() or "nssai" in fs.name.lower():
        vals.extend(_SNSSAI_POOL)
    elif "dnn" in fs.name.lower():
        vals.extend(_DNN_POOL)
    elif "mcc" in fs.name.lower():
        vals.extend(_PLMN_MCC_POOL)
    elif "mnc" in fs.name.lower():
        vals.extend(_PLMN_MNC_POOL)
    elif "scope" in fs.name.lower():
        vals.extend(_SCOPE_POOL)

    # 3. String type: length boundaries
    if fs.type == "string":
        if not fs.enum:
            vals.append("fuzz-value")     # baseline non-empty string
        if fs.min_length > 0:
            vals.append("")               # below min
            if fs.min_length > 1:
                vals.append("A" * (fs.min_length - 1))
            vals.append("A" * fs.min_length)
        if fs.max_length > 0:
            vals.append("A" * fs.max_length)
            vals.append("A" * (fs.max_length + 1))
            vals.append("A" * (fs.max_length * 2))
        else:
            vals.extend(["", "A" * 64, "A" * 256, "A" * 1024])
        # Universal string injections
        vals.extend([
            "",
            "\x00",
            "\x00injected",
            "\x00" * 8,
            "../etc/passwd",
            "null",
            "undefined",
            "true",
            "false",
        ])

    # 4. Integer type: boundaries
    elif fs.type in ("integer", "number"):
        if fs.minimum is not None:
            vals.extend([int(fs.minimum) - 1, int(fs.minimum), int(fs.minimum) + 1])
        if fs.maximum is not None:
            vals.extend([int(fs.maximum) - 1, int(fs.maximum), int(fs.maximum) + 1])
        vals.extend([0, 1, -1, 2**15, 2**16, 2**31 - 1, 2**31, 2**32, 2**63 - 1])

    # 5. Array type: count boundaries (FivGeeFuzz + open5GS array overflow)
    elif fs.type == "array":
        vals.extend([
            [],            # empty — FivGeeFuzz Bug 1 class (index[0] without length check)
            [None],        # array with null element
        ])
        if fs.max_items > 0:
            vals.append([f"item-{i}" for i in range(fs.max_items)])
            vals.append([f"item-{i}" for i in range(fs.max_items + 1)])
            vals.append([f"item-{i}" for i in range(fs.max_items * 2)])
        else:
            # No max — probe known overflow thresholds from open5GS fixed arrays
            vals.extend([
                [f"item-{i}" for i in range(8)],    # OGS_MAX_NUM_OF_SLICE - 1
                [f"item-{i}" for i in range(9)],    # OGS_MAX_NUM_OF_SLICE overflow
                [f"item-{i}" for i in range(16)],
                [f"item-{i}" for i in range(32)],
                [f"item-{i}" for i in range(128)],
            ])

    # 6. Boolean type
    elif fs.type == "boolean":
        vals.extend([True, False, None, "true", "false", 1, 0])

    # 7. Object type
    elif fs.type == "object":
        vals.extend([{}, None, "not-an-object", []])

    # 8. Required field: include None (absent) — triggers MandatoryFieldMissing
    if fs.required:
        vals.append(None)

    # 9. Nullable fields: None is always valid
    if fs.nullable:
        vals.append(None)

    # 10. Type mismatch (FivGeeFuzz Bug 3/6 class)
    vals.extend(_TYPE_MISMATCHES.get(fs.type, []))

    # Deduplicate while preserving order
    seen: list = []
    for v in vals:
        # Use (type, repr) as dedup key to handle unhashable values like dicts/lists
        key = (type(v).__name__, repr(v))
        if key not in [( type(s).__name__, repr(s)) for s in seen]:
            seen.append(v)
    return seen


# ---------------------------------------------------------------------------
# Body builders
# ---------------------------------------------------------------------------

def _default_value(fs: FieldSchema) -> Any:
    """Return a sensible default value for a field based on its schema."""
    if fs.enum:
        return fs.enum[0]
    if "supi" in fs.name.lower():
        return "imsi-001010000000001"
    if fs.format == "uuid" or (fs.type == "string" and fs.name.lower().endswith("id")):
        return "11111111-1111-1111-1111-111111111111"
    if fs.format == "uri":
        return "http://127.0.0.1:7777/callback"
    if fs.format == "date-time":
        return "2030-01-01T00:00:00Z"
    return {
        "string": "fuzz-value",
        "integer": 1,
        "number": 1.0,
        "boolean": True,
        "array": [],
        "object": {},
    }.get(fs.type, "fuzz-value")


def build_valid_body(ep: EndpointSpec, defaults: dict[str, Any] | None = None) -> dict:
    """
    Build a minimal valid request body using required fields only.
    Optional fields are omitted — this is the baseline for FivGeeFuzz scenarios.

    defaults: caller-supplied overrides (e.g. plmn_mcc, supi from training config)
    """
    body: dict[str, Any] = {}
    overrides = defaults or {}
    for fs in ep.body_fields:
        if fs.read_only:
            continue
        if fs.required:
            body[fs.name] = overrides.get(fs.name, _default_value(fs))
    return body


def build_full_body(ep: EndpointSpec, defaults: dict[str, Any] | None = None) -> dict:
    """Build a body with all fields (required + optional) filled with valid defaults."""
    body: dict[str, Any] = {}
    overrides = defaults or {}
    for fs in ep.body_fields:
        if fs.read_only:
            continue
        body[fs.name] = overrides.get(fs.name, _default_value(fs))
    return body


def build_missing_required(ep: EndpointSpec, defaults: dict[str, Any] | None,
                             omit_field: str) -> dict:
    """
    Body with one required field removed.
    Triggers 'MandatoryFieldMissing' / nil-deref in open5GS/free5GC parsers.
    """
    body = build_valid_body(ep, defaults)
    body.pop(omit_field, None)
    return body


def build_missing_optional(ep: EndpointSpec, defaults: dict[str, Any] | None,
                             omit_field: str) -> dict:
    """
    Body with one optional field deliberately absent — FivGeeFuzz Bug 1/2/5 class.

    free5GC code commonly does:
        supportedFeatures := c.QueryArray("supported-features")
        use(supportedFeatures[0])   ← panic if array is empty
    This body omits the optional field to trigger that code path.
    """
    body = build_full_body(ep, defaults)
    body.pop(omit_field, None)
    return body


def build_type_mismatch(ep: EndpointSpec, defaults: dict[str, Any] | None,
                         target_field: str) -> list[dict]:
    """
    Bodies with wrong type for target_field — FivGeeFuzz Bug 3/6 class.

    free5GC uses deepcopy + unsafe type assertions:
        result := deepcopy.Copy(msg).(models.ConcreteType)  ← panics on wrong type
    Returns one body per mismatch variant.
    """
    base = build_full_body(ep, defaults)
    fs = next((f for f in ep.body_fields if f.name == target_field), None)
    if fs is None:
        return []
    bodies = []
    for wrong_val in _TYPE_MISMATCHES.get(fs.type, []):
        body = copy.deepcopy(base)
        body[target_field] = wrong_val
        bodies.append(body)
    return bodies


# ---------------------------------------------------------------------------
# FivGeeFuzz attack scenario generators
# ---------------------------------------------------------------------------

# Max scenarios per operation — keeps the RL action space tractable.
# FivGeeFuzz findings show crashes come from the first few omitted fields/type
# mismatches; exhaustive coverage of 80+ optional params adds noise not signal.
_MAX_OMIT_PER_OP  = 20
_MAX_TYPE_PER_OP  = 20


def fivgee_omit_optional_scenarios(
        ep: EndpointSpec,
        defaults: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """
    Generate one body per optional field, with that field omitted.
    Reproduces FivGeeFuzz Bug 1 (array[0] without length check),
    Bug 2 (nil unmarshal on missing optional), Bug 5 (nil pointer on *time.Time).

    Capped at _MAX_OMIT_PER_OP scenarios: body fields first (more likely to crash
    handler logic), then query params.

    Returns: list of {"omitted_field": str, "method": str, "path": str, "body": dict}
    """
    scenarios = []
    for fname in ep.optional_body_fields:
        if len(scenarios) >= _MAX_OMIT_PER_OP:
            break
        scenarios.append({
            "attack_class": "fivgee_omit_optional",
            "omitted_field": fname,
            "method": ep.method,
            "path": ep.path,
            "operation_id": ep.operation_id,
            "body": build_missing_optional(ep, defaults, fname),
        })
    # Fill remaining slots with query param omissions
    remaining = _MAX_OMIT_PER_OP - len(scenarios)
    for qpname in ep.optional_query_params[:remaining]:
        scenarios.append({
            "attack_class": "fivgee_omit_query_param",
            "omitted_field": qpname,
            "method": ep.method,
            "path": ep.path,
            "operation_id": ep.operation_id,
            "body": build_full_body(ep, defaults),
            "omit_query_param": qpname,
        })
    return scenarios


def fivgee_type_mismatch_scenarios(
        ep: EndpointSpec,
        defaults: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """
    Generate bodies with wrong types for structured fields.
    Reproduces FivGeeFuzz Bug 3 (malformed NSSAI), Bug 6 (unsafe type assertion).

    Returns: list of {"target_field", "wrong_value", "method", "path", "body"}
    """
    scenarios = []
    for fs in ep.body_fields:
        if len(scenarios) >= _MAX_TYPE_PER_OP:
            break
        if fs.type in ("object", "array"):
            for wrong_val in _TYPE_MISMATCHES.get(fs.type, []):
                if len(scenarios) >= _MAX_TYPE_PER_OP:
                    break
                base = build_full_body(ep, defaults)
                base[fs.name] = wrong_val
                scenarios.append({
                    "attack_class": "fivgee_type_mismatch",
                    "target_field": fs.name,
                    "wrong_value": wrong_val,
                    "method": ep.method,
                    "path": ep.path,
                    "operation_id": ep.operation_id,
                    "body": base,
                })
    return scenarios


# ---------------------------------------------------------------------------
# Cross-Service Token Attack (FivGeeFuzz Bug 8)
# ---------------------------------------------------------------------------

# free5GC VerifyOAuth bug: errors.Wrapf(nil, "verify OAuth scope") returns nil,
# so any scope string passes any NF's scope check.
# These payloads send a token with scope_a's scope to scope_b's NF endpoint.

_CROSS_SERVICE_PAIRS: list[tuple[str, str, str, str]] = [
    # (scope_in_token,    requester_nf, target_nf, target_endpoint_prefix)
    ("nudm-sdm",          "UDM",  "NRF",  "/nnrf-nfm"),
    ("nnrf-disc",         "NRF",  "AMF",  "/namf-comm"),
    ("nsmf-pdusession",   "SMF",  "UDM",  "/nudm-sdm"),
    ("namf-comm",         "AMF",  "SMF",  "/nsmf-pdusession"),
    ("nudr-dr",           "UDR",  "AUSF", "/nausf-auth"),
    ("nausf-auth",        "AUSF", "PCF",  "/npcf-smpolicycontrol"),
    ("npcf-smpolicycontrol","PCF","NRF",  "/nnrf-disc"),
    ("nudm-ueau",         "UDM",  "AMF",  "/namf-evts"),
]


def cross_service_token_payloads() -> list[dict[str, Any]]:
    """
    Return a list of cross-service token attack descriptors.

    Each entry describes:
    - How to obtain a token (NRF /oauth2/token request body)
    - Which NF and endpoint to send it to
    - The expected outcome (should fail scope check; in vulnerable free5GC it doesn't)

    The token itself is a real JWT requested from the NRF — not forged.
    The attack works because free5GC's VerifyOAuth ignores scope mismatch.
    """
    payloads = []
    for scope, req_nf, tgt_nf, tgt_prefix in _CROSS_SERVICE_PAIRS:
        payloads.append({
            "attack_class": "cross_service_token",
            # Step 1: obtain token with this scope from NRF
            "token_request": {
                "method": "POST",
                "path": "/nnrf-nfm/v1/oauth2/token",
                "body": {
                    "grant_type":   "client_credentials",
                    "nfInstanceId": "11111111-1111-1111-1111-111111111111",
                    "nfType":       req_nf,
                    "targetNfType": tgt_nf,
                    "scope":        scope,
                },
            },
            # Step 2: reuse token against a different NF's endpoint
            "reuse_target_nf":     tgt_nf,
            "reuse_endpoint_prefix": tgt_prefix,
            "scope_in_token":      scope,
            "expected_result":     "scope_rejected",
            "free5gc_result":      "scope_accepted_due_to_nil_wrapf_bug",
        })
    return payloads


# ---------------------------------------------------------------------------
# Spec-semantic scenario generators (go beyond FivGeeFuzz structural mutations)
# ---------------------------------------------------------------------------

# Max per operation — same budget as omit/type
_MAX_OMIT_REQ_PER_OP   = 10   # required-field omit (fewer required fields exist)
_MAX_FIELD_VAL_PER_OP  = 30   # field-value mutations (cap per operation)


def spec_omit_required_scenarios(
        ep: EndpointSpec,
        defaults: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """
    Remove each required body field in turn.

    Unlike FivGeeFuzz Bug 1/2/5 (optional omit), required-field omission hits a
    different code path: parsers that validate presence raise MandatoryFieldMissing,
    but handlers that skip validation dereference a nil pointer directly.

    Fields already covered by hand-crafted templates (nfType, nfStatus for NRF
    RegisterNFInstance; supi/dnn for SMF PostSmContexts; etc.) are excluded to
    avoid duplicating body_fuzz and hand-crafted message actions.

    Returns list of {"attack_class", "omitted_field", "method", "path", "operation_id"}
    """
    # Hand-crafted templates already exercise these exact (operation, field) pairs.
    # Generating them again via spec would be pure duplication.
    _HAND_CRAFTED_OMIT: set[tuple[str, str]] = {
        ('RegisterNFInstance',  'nfType'),
        ('RegisterNFInstance',  'nfStatus'),
        ('PostSmContexts',      'supi'),
        ('PostSmContexts',      'dnn'),
        ('CreateSmPolicy',      'supi'),
        ('CreateUEContext',     'supi'),
        ('ChargingDataCreate',  'supi'),
        ('UEAuthentication',    'supiOrSuci'),
    }
    scenarios = []
    for fname in ep.required_body_fields[:_MAX_OMIT_REQ_PER_OP]:
        if (ep.operation_id, fname) in _HAND_CRAFTED_OMIT:
            continue
        scenarios.append({
            "attack_class":      "spec_omit_required",
            "omitted_field":     fname,
            "method":            ep.method,
            "path":              ep.path,
            "operation_id":      ep.operation_id,
            "field_was_required": True,
        })
    return scenarios


# ---------------------------------------------------------------------------
# Spec-constraint mutation values — distinct from body_fuzz generic mutations
# ---------------------------------------------------------------------------

def _spec_constraint_mutations(fs: FieldSchema) -> list[Any]:
    """
    Return only mutation values derived from spec-specific knowledge.

    body_fuzz (templates.py) already covers generic string/int/bool mutations
    (empty string, oversized, NULL byte, INT32_MAX+1, etc.).  This function
    returns ONLY what the spec tells us beyond those generics:

    1. Enum violations  — values not in the enum that the spec defines.
                          body_fuzz cannot produce these because it doesn't
                          know the valid enum set.
    2. 5G-semantic pool — SUPI/UUID/SNSSAI/DNN/PLMN/scope variants by field name.
                          body_fuzz sends generic strings; spec names give us
                          protocol-meaningful boundary cases.
    3. Explicit range boundaries — when the spec defines minimum/maximum or
                          minLength/maxLength, generate values exactly at and
                          just outside those bounds.  body_fuzz probes generic
                          INT32 boundaries which may not match the spec range.
    4. Array cardinality — empty array and max+1 when spec constrains minItems/maxItems.
    5. Null for required non-nullable — {"field": null} is different from field absent
                          and exercises a distinct code path in type-asserting parsers.
    """
    vals: list[Any] = []

    # 1. Enum: only invalid values (valid ones are uninteresting — they pass)
    if fs.enum:
        vals.append("")                          # empty — not in enum
        vals.append("INVALID_ENUM_VALUE")        # clearly bad
        vals.append(str(fs.enum[0]) + "_FUZZ")  # corrupted valid value
        # Also include all valid enum values so RL can learn which paths they open
        vals.extend(fs.enum)
        return _dedup(vals)

    # 2. 5G-semantic pool by field name
    name = fs.name.lower()
    if "supi" in name or "suci" in name:
        vals.extend(_SUPI_POOL)
    elif "nssai" in name or "snssai" in name:
        vals.extend(_SNSSAI_POOL)
    elif "uuid" in name or (name.endswith("id") and fs.format == "uuid"):
        vals.extend(_UUID_POOL)
    elif "dnn" in name:
        vals.extend(_DNN_POOL)
    elif "mcc" in name:
        vals.extend(_PLMN_MCC_POOL)
    elif "mnc" in name:
        vals.extend(_PLMN_MNC_POOL)
    elif "scope" in name:
        vals.extend(_SCOPE_POOL)

    if vals:
        # 5G-semantic field found — also add null for required non-nullable
        if fs.required and not fs.nullable:
            vals.append(None)
        return _dedup(vals)

    # 3. Explicit spec range / length boundaries (not already in body_fuzz generic set)
    if fs.type == "string":
        if fs.min_length > 0:
            vals.append("A" * (fs.min_length - 1))   # just below minimum
            vals.append("A" * fs.min_length)           # at minimum
        if fs.max_length > 0:
            vals.append("A" * fs.max_length)           # at maximum
            vals.append("A" * (fs.max_length + 1))     # just above maximum
        if fs.pattern:
            vals.append("PATTERN_VIOLATION_@#$%")

    elif fs.type in ("integer", "number"):
        if fs.minimum is not None:
            vals.append(int(fs.minimum) - 1)           # below min
            vals.append(int(fs.minimum))                # at min
        if fs.maximum is not None:
            vals.append(int(fs.maximum))                # at max
            vals.append(int(fs.maximum) + 1)            # above max

    # 4. Array cardinality
    elif fs.type == "array":
        vals.append([])                                  # empty — minItems violation
        if fs.max_items > 0:
            vals.append([f"item-{i}" for i in range(fs.max_items + 1)])  # above max

    if not vals:
        # No spec-specific constraint to exploit — skip (body_fuzz covers generics)
        return []

    # 5. Null for required non-nullable (always unique — body_fuzz drops the field,
    #    this sends the field explicitly as null)
    if fs.required and not fs.nullable:
        vals.append(None)

    return _dedup(vals)


def _dedup(vals: list[Any]) -> list[Any]:
    seen: list = []
    for v in vals:
        key = (type(v).__name__, repr(v))
        if key not in [(type(s).__name__, repr(s)) for s in seen]:
            seen.append(v)
    return seen


def spec_field_value_scenarios(
        ep: EndpointSpec,
        defaults: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """
    One scenario per (field, mutation_value) pair — but only for values where
    the spec provides specific knowledge that body_fuzz doesn't have:
      - enum violations (body_fuzz doesn't know the valid enum set)
      - 5G-semantic pools (SUPI/UUID/NSSAI/DNN by field name)
      - explicit spec range boundaries (minimum/maximum/minLength/maxLength)
      - array cardinality violations (minItems/maxItems)
      - null for required non-nullable fields

    Generic string/int/bool mutations already covered by body_fuzz are excluded.

    Capped at _MAX_FIELD_VAL_PER_OP; required+enum fields prioritised first.
    """
    scenarios: list[dict[str, Any]] = []

    def _priority(fs: FieldSchema) -> int:
        if fs.required and fs.enum:  return 0   # required enum — highest crash prob
        if fs.enum:                  return 1   # optional enum
        if fs.required:              return 2   # required non-enum (semantic/range)
        return 3

    fields_sorted = sorted(ep.body_fields, key=_priority)
    fields_sorted += sorted(ep.query_params, key=_priority)

    for fs in fields_sorted:
        if len(scenarios) >= _MAX_FIELD_VAL_PER_OP:
            break
        for val in _spec_constraint_mutations(fs):
            if len(scenarios) >= _MAX_FIELD_VAL_PER_OP:
                break
            scenarios.append({
                "attack_class":  "spec_field_value",
                "field":         fs.name,
                "value":         val,
                "field_type":    fs.type,
                "is_required":   fs.required,
                "has_enum":      bool(fs.enum),
                "method":        ep.method,
                "path":          ep.path,
                "operation_id":  ep.operation_id,
            })

    return scenarios


# ---------------------------------------------------------------------------
# Producer-consumer sequence builder
# ---------------------------------------------------------------------------

def producer_consumer_sequence(ep: EndpointSpec) -> list[str]:
    """
    Return ordered list of operation IDs that must run before ep.
    Derived from EndpointSpec.depends_on (inferred by spec_parser).

    Use this to build multi-step StateTransition sequences in adapter.py.
    """
    return list(ep.depends_on)


# Trailing custom-verb segments used by 3GPP SBI for non-REST sub-operations.
# These are NOT path parameters; they sit after a {resourceId} segment and name
# an action performed on that resource (POST /coll/{id}/update, /delete, …).
# spec_parser._infer_depends_on only handles REST GET/PATCH/DELETE on /coll/{id}
# and misses these, which is why depends_on is empty for most SBI consumers.
_CUSTOM_VERBS: frozenset[str] = frozenset({
    "update", "delete", "modify", "release", "create",
    "subscribe", "unsubscribe", "notify", "transfer",
    "pcscf-restoration", "events-subscription", "deliver",
    "send-mo-data", "send-mt-data", "associate", "deassociate",
    "transfer-update", "smContextStatusNotify",
})


def _norm_path(path: str) -> str:
    """Normalise a path for comparison: strip a single trailing slash."""
    if len(path) > 1 and path.endswith("/"):
        return path[:-1]
    return path


def _is_param_seg(seg: str) -> bool:
    return seg.startswith("{") and seg.endswith("}")


def infer_producer_op(
        method: str,
        path: str,
        op_table: dict[str, tuple[str, str]],
) -> str | None:
    """
    Given a consumer operation (method, path) and the full table of operations
    ``{operation_id: (method, path)}``, return the operationId of the producer
    that creates the resource this consumer references — or None.

    Handles both REST and 3GPP-custom shapes:
      GET/PATCH/DELETE /coll/{id}            → POST (or PUT) /coll
      POST            /coll/{id}/update      → POST (or PUT) /coll
      POST            /coll/{id}/delete      → POST (or PUT) /coll

    The producer is the POST (preferred) or PUT on the parent collection path.
    A create itself (POST /coll, with no {id} in its tail) has no producer and
    returns None.
    """
    segs = [s for s in path.split("/") if s]
    if not segs:
        return None

    # 1. Strip a trailing custom-verb segment, but only when it sits directly
    #    after a {param} — otherwise it's an ordinary collection name, not a verb.
    if (not _is_param_seg(segs[-1])
            and len(segs) >= 2 and _is_param_seg(segs[-2])
            and segs[-1].lower() in _CUSTOM_VERBS):
        segs = segs[:-1]

    # 2. The next segment must be the resource-id {param}; strip it to reach the
    #    collection.  If it isn't a param, this op targets a collection directly
    #    (it's a create/list, not a consumer of a created resource) → no producer.
    if not (segs and _is_param_seg(segs[-1])):
        return None
    segs = segs[:-1]
    if not segs:
        return None

    collection = _norm_path("/" + "/".join(segs))

    # 3. Find a producer on the collection path: POST preferred, PUT fallback.
    for want in ("POST", "PUT"):
        for op_id, (m, p) in op_table.items():
            if m.upper() == want and _norm_path(p) == collection:
                return op_id
    return None


# ---------------------------------------------------------------------------
# Bulk mutation table (used by generate_spec_mutations.py)
# ---------------------------------------------------------------------------

def compute_all_mutations(ep: EndpointSpec) -> dict[str, Any]:
    """
    Compute the full mutation table for one endpoint.
    Returned dict is serialisable to JSON.
    """
    field_mutations: dict[str, list] = {}
    for fs in ep.body_fields:
        field_mutations[fs.name] = _serialise(mutations_for_field(fs))

    query_mutations: dict[str, list] = {}
    for qs in ep.query_params:
        query_mutations[qs.name] = _serialise(mutations_for_field(qs))

    return {
        "nf": ep.nf,
        "method": ep.method,
        "path": ep.path,
        "operation_id": ep.operation_id,
        "required_body_fields": ep.required_body_fields,
        "optional_body_fields": ep.optional_body_fields,
        "required_query_params": ep.required_query_params,
        "optional_query_params": ep.optional_query_params,
        "depends_on": ep.depends_on,
        "field_mutations": field_mutations,
        "query_mutations": query_mutations,
        "fivgee_omit_optional": [
            {k: v for k, v in s.items() if k != "body"}   # bodies stored separately
            for s in fivgee_omit_optional_scenarios(ep)
        ],
        "fivgee_type_mismatch": [
            {k: v for k, v in s.items() if k != "body"}
            for s in fivgee_type_mismatch_scenarios(ep)
        ],
        "spec_omit_required": spec_omit_required_scenarios(ep),
        "spec_field_value": [
            {k: v for k, v in s.items()}   # all fields are scalars — no body to strip
            for s in spec_field_value_scenarios(ep)
        ],
        "valid_body_baseline": build_valid_body(ep),
    }


def _serialise(vals: list[Any]) -> list[Any]:
    """Make a mutation list JSON-serialisable (replace non-serialisable with repr)."""
    result = []
    for v in vals:
        if v is None or isinstance(v, (bool, int, float, str, list, dict)):
            result.append(v)
        else:
            result.append(repr(v))
    return result
