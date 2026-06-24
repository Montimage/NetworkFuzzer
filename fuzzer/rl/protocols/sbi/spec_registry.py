#!/usr/bin/env python3
"""
Global spec registry — parse once, share everywhere.

All components (SbiAdapter, replay_crash, generate_spec_mutations, …)
import from here rather than creating their own SpecParser instances.

Thread-safe lazy loading: specs are parsed on first get_endpoints() call
and cached in a module-level dict for the lifetime of the process.

Usage:
    from fuzzer.rl.protocols.sbi.spec_registry import get_endpoints, get_all_endpoints

    # Lazy: load only NRF specs when needed
    nrf_endpoints = get_endpoints('NRF')

    # Eager: warm all specs at startup (e.g. in train_protocol.py)
    all_specs = get_all_endpoints()

    # Lookup a single operation by ID (used by adapter.build_message)
    ep = get_endpoint_by_operation_id('GetSharedData')
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Optional

from .spec_parser import EndpointSpec, SpecParser

logger = logging.getLogger(__name__)

SPECS_DIR = Path(__file__).parent / "openapi_specs"

# Maps NF type → list of spec filenames to load.
# Order matters: files later in the list may override earlier ones for the
# same operationId if the NF spec references the common data spec directly.
NF_SPEC_FILES: dict[str, list[str]] = {
    "NRF": [
        "TS29510_Nnrf_NFManagement.yaml",
        "TS29510_Nnrf_NFDiscovery.yaml",
        "TS29510_Nnrf_AccessToken.yaml",
    ],
    "AMF": [
        "TS29518_Namf_Communication.yaml",
        "TS29518_Namf_EventExposure.yaml",
    ],
    "SMF": [
        "TS29502_Nsmf_PDUSession.yaml",
        "TS29502_Nsmf_EventExposure.yaml",
    ],
    "UDM": [
        "TS29503_Nudm_SDM.yaml",
        "TS29503_Nudm_UECM.yaml",
        "TS29503_Nudm_UEAU.yaml",
        # All remaining UDM service groups free5GC routes (NFs/udm/internal/sbi/api_*.go):
        # event-exposure, parameter-provision, MT, NIDD-auth, report-sm-delivery-status,
        # service-specific-auth, UE-ID.  Previously omitted → those handlers were 0% covered.
        "TS29503_Nudm_EE.yaml",
        "TS29503_Nudm_PP.yaml",
        "TS29503_Nudm_MT.yaml",
        "TS29503_Nudm_NIDDAU.yaml",
        "TS29503_Nudm_RSDS.yaml",
        "TS29503_Nudm_SSAU.yaml",
        "TS29503_Nudm_UEID.yaml",
    ],
    "UDR": [
        # Nudr_DR is the aggregator; its 103 paths are $refs into these data specs
        # (resolved by the parser's path-item $ref handling).  Listing only Nudr_DR
        # is enough — the others are pulled in via cross-file ref — but they must be
        # present on disk (fetch_specs.sh fetches them).
        "TS29504_Nudr_DR.yaml",
    ],
    "AUSF": [
        "TS29509_Nausf_UEAuthentication.yaml",
        "TS29509_Nausf_SoRProtection.yaml",
        "TS29509_Nausf_UPUProtection.yaml",
    ],
    "PCF": [
        "TS29507_Npcf_AMPolicyControl.yaml",
        "TS29512_Npcf_SMPolicyControl.yaml",
        "TS29514_Npcf_PolicyAuthorization.yaml",
    ],
    "NSSF": [
        "TS29531_Nnssf_NSSelection.yaml",
        "TS29531_Nnssf_NSSAIAvailability.yaml",
    ],
    "BSF": [
        "TS29521_Nbsf_Management.yaml",
    ],
    "CHF": [
        "TS29594_Nchf_ConvergedCharging.yaml",
    ],
}

ALL_NFS: list[str] = list(NF_SPEC_FILES.keys())

# ---------------------------------------------------------------------------
# Module-level state (private)
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_registry: dict[str, list[EndpointSpec]] = {}          # nf → endpoints
_op_index: dict[str, EndpointSpec] = {}                # operationId → endpoint
_parser: Optional[SpecParser] = None
_specs_available: Optional[bool] = None                # None = not yet checked


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def specs_available() -> bool:
    """Return True if the openapi_specs/ directory exists and has YAML files."""
    global _specs_available
    if _specs_available is None:
        _specs_available = (
            SPECS_DIR.exists()
            and any(SPECS_DIR.glob("*.yaml"))
        )
        if not _specs_available:
            logger.info(
                "spec_registry: openapi_specs/ not found — "
                "run scripts/fetch_specs.sh to enable spec-driven fuzzing"
            )
    return _specs_available


def get_endpoints(nf: str) -> list[EndpointSpec]:
    """
    Return parsed EndpointSpec list for a given NF type.
    Parses the YAML files on first call; cached on subsequent calls.
    Returns [] if specs are not available.
    """
    nf = nf.upper()
    if nf not in _registry:
        with _lock:
            if nf not in _registry:
                _registry[nf] = _load_nf(nf)
                for ep in _registry[nf]:
                    if ep.operation_id:
                        _op_index[ep.operation_id] = ep
    return _registry[nf]


def get_all_endpoints() -> dict[str, list[EndpointSpec]]:
    """
    Eagerly load and cache specs for all known NFs.
    Call once at process startup to amortise parse time.
    Returns mapping nf → endpoint list.
    """
    for nf in ALL_NFS:
        get_endpoints(nf)
    return dict(_registry)


def get_endpoint_by_operation_id(operation_id: str) -> Optional[EndpointSpec]:
    """
    Look up a single EndpointSpec by its operationId string.
    Returns None if not found.
    Triggers a full load of all specs on first call if the op_index is empty.
    """
    if not _op_index and specs_available():
        get_all_endpoints()
    return _op_index.get(operation_id)


def get_endpoints_for_path_prefix(prefix: str) -> list[EndpointSpec]:
    """
    Return all endpoints whose path starts with prefix.
    Useful for filtering to a specific service, e.g. '/nudm-sdm'.
    """
    result: list[EndpointSpec] = []
    for nf in ALL_NFS:
        for ep in get_endpoints(nf):
            if ep.path.startswith(prefix):
                result.append(ep)
    return result


def endpoint_count() -> dict[str, int]:
    """Return {nf: endpoint_count} for all loaded NFs."""
    return {nf: len(eps) for nf, eps in _registry.items()}


def reset() -> None:
    """Clear the registry cache. Mainly for testing."""
    global _specs_available
    with _lock:
        _registry.clear()
        _op_index.clear()
        _specs_available = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_nf(nf: str) -> list[EndpointSpec]:
    if not specs_available():
        return []

    global _parser
    if _parser is None:
        _parser = SpecParser(SPECS_DIR)

    endpoints: list[EndpointSpec] = []
    for fname in NF_SPEC_FILES.get(nf, []):
        try:
            batch = _parser.load_nf(nf, fname)
            endpoints.extend(batch)
            logger.debug("spec_registry: loaded %s → %d endpoints", fname, len(batch))
        except Exception as exc:
            logger.warning("spec_registry: failed loading %s: %s", fname, exc)

    logger.info("spec_registry: %s → %d total endpoints", nf, len(endpoints))
    return endpoints
