#!/usr/bin/env python3
"""
Offline spec mutation seed generator.

Parses all 3GPP OpenAPI YAML specs via the spec registry, computes mutation
tables for every endpoint × field using spec_mutator, and writes the result
to fuzzer/data/spec_mutations.json.

Run once after fetching specs:
    python scripts/generate_spec_mutations.py

Output file is committed to the repo so the fuzzer can load mutations at
runtime without re-parsing YAML or making any LLM calls.

Usage:
    python scripts/generate_spec_mutations.py [--output PATH] [--nf NRF,AMF,...]
                                               [--stats] [--pretty]
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

# ── Bootstrap path so we can import the fuzzer package from scripts/ ──────────
SCRIPT_DIR = Path(__file__).parent
REPO_ROOT   = SCRIPT_DIR.parent
sys.path.insert(0, str(REPO_ROOT))

# Register package stubs for intermediate packages that pull in gym/torch at
# import time (fuzzer.rl.base, fuzzer.rl.protocols).  The spec modules only
# depend on yaml/json — they don't need any RL machinery.
import types as _types
for _pkg in ('fuzzer', 'fuzzer.rl', 'fuzzer.rl.protocols'):
    if _pkg not in sys.modules:
        sys.modules[_pkg] = _types.ModuleType(_pkg)

# Register the sbi sub-package with the correct __path__ so relative imports
# inside spec_registry / spec_parser / spec_mutator resolve correctly.
_sbi_pkg = _types.ModuleType('fuzzer.rl.protocols.sbi')
_sbi_pkg.__path__ = [str(REPO_ROOT / 'fuzzer' / 'rl' / 'protocols' / 'sbi')]
_sbi_pkg.__package__ = 'fuzzer.rl.protocols.sbi'
sys.modules['fuzzer.rl.protocols.sbi'] = _sbi_pkg

from fuzzer.rl.protocols.sbi.spec_registry import (
    get_all_endpoints,
    get_endpoints,
    specs_available,
    endpoint_count,
    ALL_NFS,
    SPECS_DIR,
)
from fuzzer.rl.protocols.sbi.spec_mutator import (
    compute_all_mutations,
    cross_service_token_payloads,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s  %(name)s  %(message)s",
)
logger = logging.getLogger("generate_spec_mutations")

DEFAULT_OUTPUT = REPO_ROOT / "fuzzer" / "data" / "spec_mutations.json"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate spec-driven mutation seeds from 3GPP OpenAPI YAML files."
    )
    parser.add_argument(
        "--output", default=str(DEFAULT_OUTPUT),
        help=f"Output JSON file path (default: {DEFAULT_OUTPUT})"
    )
    parser.add_argument(
        "--nf", default="",
        help="Comma-separated NF types to include (default: all). "
             "Example: --nf NRF,AMF,UDM"
    )
    parser.add_argument(
        "--stats", action="store_true",
        help="Print statistics only, do not write output file"
    )
    parser.add_argument(
        "--pretty", action="store_true",
        help="Pretty-print JSON output (larger file, human-readable)"
    )
    args = parser.parse_args()

    output_path = Path(args.output)
    target_nfs = [n.strip().upper() for n in args.nf.split(",") if n.strip()] or ALL_NFS

    # ── Check specs are available ─────────────────────────────────────────────
    if not specs_available():
        logger.error(
            "OpenAPI specs not found at %s\n"
            "Run:  bash scripts/fetch_specs.sh",
            SPECS_DIR,
        )
        sys.exit(1)

    logger.info("generating mutations for NFs: %s", ", ".join(target_nfs))
    t0 = time.time()

    # ── Parse all requested NFs ───────────────────────────────────────────────
    if set(target_nfs) == set(ALL_NFS):
        get_all_endpoints()   # warm all at once
    else:
        for nf in target_nfs:
            get_endpoints(nf)

    counts = endpoint_count()
    total_eps = sum(counts.get(nf, 0) for nf in target_nfs)
    logger.info("loaded %d total endpoints across %d NFs", total_eps, len(target_nfs))

    # ── Compute mutation tables ───────────────────────────────────────────────
    output: dict = {
        "_meta": {
            "generated_by": "scripts/generate_spec_mutations.py",
            "specs_dir": str(SPECS_DIR),
            "nfs": target_nfs,
            "total_endpoints": total_eps,
        },
        "operations": {},            # operation_id → mutation table
        "cross_service_tokens": [],  # FivGeeFuzz Bug 8 attack payloads
        "nf_index": {},              # nf → [operation_ids]
        "path_index": {},            # path → [operation_ids]
    }

    total_fields = 0
    total_mutations = 0

    for nf in target_nfs:
        nf_op_ids: list[str] = []
        for ep in get_endpoints(nf):
            if not ep.operation_id:
                continue

            table = compute_all_mutations(ep)
            output["operations"][ep.operation_id] = table

            # Build path index
            path_key = f"{ep.method} {ep.path}"
            output["path_index"].setdefault(path_key, []).append(ep.operation_id)

            nf_op_ids.append(ep.operation_id)

            # Accumulate stats
            for field_muts in table["field_mutations"].values():
                total_fields += 1
                total_mutations += len(field_muts)
            for query_muts in table["query_mutations"].values():
                total_fields += 1
                total_mutations += len(query_muts)

        output["nf_index"][nf] = nf_op_ids

    # ── Add cross-service token payloads ──────────────────────────────────────
    output["cross_service_tokens"] = cross_service_token_payloads()

    # ── Statistics ────────────────────────────────────────────────────────────
    elapsed = time.time() - t0
    stats = {
        "nf_endpoint_counts": {nf: counts.get(nf, 0) for nf in target_nfs},
        "total_operations":   len(output["operations"]),
        "total_fields":       total_fields,
        "total_mutations":    total_mutations,
        "cross_service_payloads": len(output["cross_service_tokens"]),
        "elapsed_seconds":    round(elapsed, 2),
    }
    output["_meta"]["stats"] = stats

    logger.info("─" * 60)
    logger.info("Operations:           %d", stats["total_operations"])
    logger.info("Fields tracked:       %d", stats["total_fields"])
    logger.info("Total mutations:      %d", stats["total_mutations"])
    logger.info("Cross-service payloads: %d", stats["cross_service_payloads"])
    for nf, count in stats["nf_endpoint_counts"].items():
        logger.info("  %-6s  %d endpoints", nf, count)
    logger.info("Elapsed: %.2fs", elapsed)
    logger.info("─" * 60)

    if args.stats:
        return

    # ── Write output ──────────────────────────────────────────────────────────
    output_path.parent.mkdir(parents=True, exist_ok=True)
    indent = 2 if args.pretty else None
    separators = None if args.pretty else (",", ":")

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=indent, separators=separators,
                  ensure_ascii=False, default=_json_default)

    size_kb = output_path.stat().st_size / 1024
    logger.info("wrote %s (%.1f KB)", output_path, size_kb)
    logger.info("")
    logger.info("Load in fuzzer:")
    logger.info("  from fuzzer.rl.protocols.sbi.spec_mutations_loader import SpecMutations")
    logger.info("  sm = SpecMutations.load()")
    logger.info("  vals = sm.field_mutations('GetSharedData', 'supported-features')")


def _json_default(obj):
    """Fallback serialiser for non-JSON-serialisable objects."""
    return repr(obj)


if __name__ == "__main__":
    main()
