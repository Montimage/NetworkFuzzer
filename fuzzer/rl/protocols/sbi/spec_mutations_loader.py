#!/usr/bin/env python3
"""
Runtime loader for pre-generated spec_mutations.json.

Provides fast, zero-YAML-parse access to spec-derived mutations.
Used by SbiAdapter, replay_crash, and any other component that needs
mutation values at runtime — without re-parsing OpenAPI YAML.

The JSON file is produced by:
    python scripts/generate_spec_mutations.py

Usage:
    from fuzzer.rl.protocols.sbi.spec_mutations_loader import SpecMutations

    sm = SpecMutations.load()                          # singleton
    vals = sm.field_mutations('GetSharedData', 'supported-features')
    ops  = sm.operations_for_nf('UDM')
    ep   = sm.operation('CreateSmContext')
    xst  = sm.cross_service_token_payloads()
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_PATH = Path(__file__).parent.parent.parent.parent / "data" / "spec_mutations.json"

_instance: Optional["SpecMutations"] = None


class SpecMutations:
    """
    Thin wrapper around spec_mutations.json.
    Thread-safe singleton via SpecMutations.load().
    Returns empty lists / dicts gracefully if file is missing.
    """

    def __init__(self, data: dict):
        self._data = data
        self._ops: dict[str, dict] = data.get("operations", {})
        self._nf_index: dict[str, list[str]] = data.get("nf_index", {})
        self._path_index: dict[str, list[str]] = data.get("path_index", {})
        self._xst: list[dict] = data.get("cross_service_tokens", [])

    # ── Singleton factory ─────────────────────────────────────────────────────

    @classmethod
    def load(cls, path: Path = DEFAULT_PATH) -> "SpecMutations":
        """Return the module-level singleton, loading from path on first call."""
        global _instance
        if _instance is None:
            _instance = cls._from_file(path)
        return _instance

    @classmethod
    def _from_file(cls, path: Path) -> "SpecMutations":
        if not path.exists():
            logger.info(
                "spec_mutations.json not found at %s — "
                "run: python scripts/generate_spec_mutations.py",
                path,
            )
            return cls({})
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            meta = data.get("_meta", {})
            stats = meta.get("stats", {})
            logger.info(
                "spec_mutations loaded: %d operations, %d mutations total",
                stats.get("total_operations", 0),
                stats.get("total_mutations", 0),
            )
            return cls(data)
        except Exception as exc:
            logger.warning("failed to load spec_mutations.json: %s", exc)
            return cls({})

    @classmethod
    def reset(cls) -> None:
        """Clear the singleton (for testing)."""
        global _instance
        _instance = None

    # ── Query API ─────────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        return bool(self._ops)

    def operation(self, operation_id: str) -> dict:
        """Return the full mutation table for an operation, or {}."""
        return self._ops.get(operation_id, {})

    def operations_for_nf(self, nf: str) -> list[str]:
        """Return list of operation IDs for a given NF type."""
        return self._nf_index.get(nf.upper(), [])

    def operations_for_path(self, method: str, path: str) -> list[str]:
        """Return operation IDs for an HTTP method + path."""
        return self._path_index.get(f"{method.upper()} {path}", [])

    def all_operation_ids(self) -> list[str]:
        return list(self._ops.keys())

    def field_mutations(self, operation_id: str, field_name: str) -> list[Any]:
        """
        Return mutation values for a specific body field in an operation.
        Falls back to query_mutations if field not found in body.
        """
        op = self._ops.get(operation_id, {})
        body_muts = op.get("field_mutations", {})
        if field_name in body_muts:
            return body_muts[field_name]
        return op.get("query_mutations", {}).get(field_name, [])

    def query_mutations(self, operation_id: str, param_name: str) -> list[Any]:
        """Return mutation values for a query parameter in an operation."""
        return self._ops.get(operation_id, {}).get(
            "query_mutations", {}
        ).get(param_name, [])

    def required_body_fields(self, operation_id: str) -> list[str]:
        return self._ops.get(operation_id, {}).get("required_body_fields", [])

    def optional_body_fields(self, operation_id: str) -> list[str]:
        return self._ops.get(operation_id, {}).get("optional_body_fields", [])

    def required_query_params(self, operation_id: str) -> list[str]:
        return self._ops.get(operation_id, {}).get("required_query_params", [])

    def optional_query_params(self, operation_id: str) -> list[str]:
        return self._ops.get(operation_id, {}).get("optional_query_params", [])

    def valid_body_baseline(self, operation_id: str) -> dict:
        """Return the pre-computed minimal valid body for an operation."""
        return self._ops.get(operation_id, {}).get("valid_body_baseline", {})

    def depends_on(self, operation_id: str) -> list[str]:
        """Return operation IDs that must precede this one (producer-consumer)."""
        return self._ops.get(operation_id, {}).get("depends_on", [])

    def fivgee_omit_optional(self, operation_id: str) -> list[dict]:
        """Return FivGeeFuzz Bug 1/2/5 scenario descriptors for an operation."""
        return self._ops.get(operation_id, {}).get("fivgee_omit_optional", [])

    def fivgee_type_mismatch(self, operation_id: str) -> list[dict]:
        """Return FivGeeFuzz Bug 3/6 scenario descriptors for an operation."""
        return self._ops.get(operation_id, {}).get("fivgee_type_mismatch", [])

    def spec_omit_required(self, operation_id: str) -> list[dict]:
        """Return spec-derived required-field omission scenario descriptors."""
        return self._ops.get(operation_id, {}).get("spec_omit_required", [])

    def spec_field_value(self, operation_id: str) -> list[dict]:
        """Return spec-derived per-field value mutation scenario descriptors."""
        return self._ops.get(operation_id, {}).get("spec_field_value", [])

    def cross_service_token_payloads(self) -> list[dict]:
        """Return all cross-service token attack descriptors (FivGeeFuzz Bug 8)."""
        return list(self._xst)

    def method_path(self, operation_id: str) -> tuple[str, str]:
        """Return (method, path) for an operation, or ('', '')."""
        op = self._ops.get(operation_id, {})
        return op.get("method", ""), op.get("path", "")

    def all_paths_for_nf(self, nf: str) -> list[tuple[str, str]]:
        """Return list of (method, path) tuples for all operations of an NF."""
        result = []
        for op_id in self.operations_for_nf(nf):
            m, p = self.method_path(op_id)
            if m and p:
                result.append((m, p))
        return result

    def summary(self) -> dict:
        """Return a short summary dict for logging."""
        meta = self._data.get("_meta", {})
        return meta.get("stats", {"available": self.is_available()})
