"""
HTTP/2 SBI protocol adapter for RL fuzzing of open5GS / free5GC NFs.

Targets the 5G Service-Based Interface (3GPP TS 29.500) over plain TCP:
  NRF (TS 29.510)  — port 7777
  AMF (TS 29.518)  — port 7777
  SMF (TS 29.502)  — port 7779
  UDM, PCF, AUSF   — port 7777

Registered as 'sbi' with the protocol adapter registry.

Spec-driven fuzzing (parse once, share everywhere):
  spec_parser.py          — parse 3GPP OpenAPI YAML → EndpointSpec/FieldSchema
  spec_registry.py        — module-level singleton, lazy-loaded per NF
  spec_mutator.py         — derive mutations from schema + FivGeeFuzz attack classes
  spec_mutations_loader.py— load pre-generated spec_mutations.json at runtime

Offline seed generation:
  python scripts/fetch_specs.sh           # download 3GPP YAML specs
  python scripts/generate_spec_mutations.py   # produce fuzzer/data/spec_mutations.json
"""

from .adapter import SbiAdapter

# Spec-driven fuzzing public API — importable from any component
from .spec_registry import (
    get_endpoints,
    get_all_endpoints,
    get_endpoint_by_operation_id,
    specs_available,
    NF_SPEC_FILES,
    ALL_NFS,
)
from .spec_mutations_loader import SpecMutations

__all__ = [
    # Adapter
    'SbiAdapter',
    # Spec registry (parse once, share everywhere)
    'get_endpoints',
    'get_all_endpoints',
    'get_endpoint_by_operation_id',
    'specs_available',
    'NF_SPEC_FILES',
    'ALL_NFS',
    # Runtime mutations loader
    'SpecMutations',
]
