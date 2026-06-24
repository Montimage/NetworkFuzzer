#!/usr/bin/env python3
"""
3GPP OpenAPI YAML spec parser for SBI fuzzing.

Parses 3GPP TS 29.x YAML files into EndpointSpec / FieldSchema dataclasses.
Handles:
  - Cross-file $ref resolution (e.g. TS29571_CommonData.yaml#/components/schemas/Supi)
  - allOf / oneOf / anyOf schema merging
  - Inline $ref chains (up to MAX_DEREF_DEPTH levels)
  - path / query / header parameters
  - Request body schema extraction

No singleton logic here — pure stateless parsing.
Use spec_registry.py for cached, shared access across components.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

MAX_DEREF_DEPTH = 12   # guard against circular $ref
SPECS_DIR = Path(__file__).parent / "openapi_specs"


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------

@dataclass
class FieldSchema:
    """Constraints and metadata for a single schema property."""
    name: str
    type: str                           # string | integer | number | boolean | array | object
    format: str = ""                    # uuid, date-time, binary, byte, int32, int64, …
    description: str = ""
    enum: list[Any] = field(default_factory=list)
    min_length: int = 0
    max_length: int = 0
    min_items: int = 0
    max_items: int = 0
    minimum: Any = None
    maximum: Any = None
    pattern: str = ""
    required: bool = False              # whether the field is in the parent's required[]
    nullable: bool = False              # OpenAPI 3.0 nullable extension
    read_only: bool = False
    write_only: bool = False
    items_type: str = ""               # for array: element type
    items_format: str = ""             # for array: element format
    items_enum: list[Any] = field(default_factory=list)


@dataclass
class EndpointSpec:
    """One HTTP operation parsed from an OpenAPI spec."""
    nf: str                             # 'NRF', 'AMF', …
    spec_file: str                      # source filename
    path: str                           # /nnrf-nfm/v1/nf-instances/{nfInstanceId}
    method: str                         # GET | POST | PUT | DELETE | PATCH
    operation_id: str
    summary: str = ""
    tags: list[str] = field(default_factory=list)
    path_params: list[FieldSchema] = field(default_factory=list)
    query_params: list[FieldSchema] = field(default_factory=list)
    header_params: list[FieldSchema] = field(default_factory=list)
    body_fields: list[FieldSchema] = field(default_factory=list)   # top-level body props
    required_body_fields: list[str] = field(default_factory=list)
    optional_body_fields: list[str] = field(default_factory=list)
    required_query_params: list[str] = field(default_factory=list)
    optional_query_params: list[str] = field(default_factory=list)
    # Producer-consumer: operation IDs that must succeed before this one
    depends_on: list[str] = field(default_factory=list)
    # Raw request body schema (for custom body builders)
    raw_body_schema: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class SpecParser:
    """
    Parse 3GPP OpenAPI YAML files into lists of EndpointSpec objects.

    Example:
        parser = SpecParser()
        endpoints = parser.load_nf('NRF', 'TS29510_Nnrf_NFManagement.yaml')
    """

    def __init__(self, specs_dir: Path = SPECS_DIR):
        self._dir = specs_dir
        # Cache of loaded raw YAML dicts, keyed by filename (cross-file $ref)
        self._file_cache: dict[str, dict] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def load_nf(self, nf: str, filename: str) -> list[EndpointSpec]:
        """Parse one spec file and return all EndpointSpec objects for that NF."""
        raw = self._load_file(filename)
        if not raw:
            return []
        components = raw.get("components", {})
        endpoints: list[EndpointSpec] = []

        # Extract service base path from the first server URL.
        # 3GPP specs use: servers: [{url: '{apiRoot}/nnrf-nfm/v1'}]
        # We strip the leading template variable so paths become absolute.
        base_path = ""
        servers = raw.get("servers", [])
        if servers and isinstance(servers[0], dict):
            server_url = servers[0].get("url", "")
            # Remove any leading {template} variables (e.g. {apiRoot}, {nfId})
            stripped = re.sub(r"^\{[^}]+\}", "", server_url)
            if stripped and stripped != server_url:
                base_path = stripped if stripped.startswith("/") else "/" + stripped

        for url_path, path_item in raw.get("paths", {}).items():
            # Resolve path-item-level $ref.  3GPP aggregator specs (e.g. Nudr_DR)
            # define each path as {"$ref": "TS29505_…yaml#/paths/~1…%7BueId%7D…"}
            # pointing at the real path-item in a data spec.  We follow it and
            # track the source file so the operation's *internal* $refs resolve
            # relative to that file, not the aggregator.
            path_item, op_file = self._resolve_path_item(path_item, filename)
            if not isinstance(path_item, dict) or not path_item:
                continue
            url_path = base_path + url_path
            # Shared parameters at path level
            path_level_params = path_item.get("parameters", [])

            for method, op in path_item.items():
                if method not in ("get", "post", "put", "delete", "patch"):
                    continue
                if not isinstance(op, dict):
                    continue

                # Merge path-level + operation-level parameters
                all_params = list(path_level_params) + list(op.get("parameters", []))

                path_params = self._parse_params(all_params, "path", op_file, components)
                query_params = self._parse_params(all_params, "query", op_file, components)
                header_params = self._parse_params(all_params, "header", op_file, components)

                body_schema = self._resolve_request_body(op, op_file, components)
                body_fields, req_fields, opt_fields = self._flatten_body(
                    body_schema, op_file, components
                )

                req_qp = [p.name for p in query_params if p.required]
                opt_qp = [p.name for p in query_params if not p.required]

                ep = EndpointSpec(
                    nf=nf,
                    spec_file=filename,
                    path=url_path,
                    method=method.upper(),
                    operation_id=op.get("operationId", ""),
                    summary=op.get("summary", ""),
                    tags=op.get("tags", []),
                    path_params=path_params,
                    query_params=query_params,
                    header_params=header_params,
                    body_fields=body_fields,
                    required_body_fields=req_fields,
                    optional_body_fields=opt_fields,
                    required_query_params=req_qp,
                    optional_query_params=opt_qp,
                    depends_on=self._infer_depends_on(url_path, method, raw),
                    raw_body_schema=body_schema,
                )
                endpoints.append(ep)

        logger.debug("spec_parser: %s → %d endpoints (%s)", filename, len(endpoints), nf)
        return endpoints

    # ── File loading ──────────────────────────────────────────────────────────

    def _load_file(self, filename: str) -> dict:
        if filename in self._file_cache:
            return self._file_cache[filename]
        path = self._dir / filename
        if not path.exists():
            logger.warning("spec file not found: %s", path)
            self._file_cache[filename] = {}
            return {}
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            self._file_cache[filename] = raw or {}
            return self._file_cache[filename]
        except Exception as exc:
            logger.warning("failed to parse %s: %s", filename, exc)
            self._file_cache[filename] = {}
            return {}

    # ── $ref resolution ───────────────────────────────────────────────────────

    def _deref(self, schema: Any, current_file: str,
                depth: int = 0) -> dict:
        """Recursively resolve $ref chains. Returns merged schema dict."""
        if depth > MAX_DEREF_DEPTH or not isinstance(schema, dict):
            return schema or {}

        if "$ref" in schema:
            ref: str = schema["$ref"]
            return self._resolve_ref(ref, current_file, depth)

        # Merge allOf / anyOf / oneOf into a single flat dict
        merged: dict = {}
        for combiner in ("allOf", "anyOf", "oneOf"):
            if combiner in schema:
                for sub in schema[combiner]:
                    resolved = self._deref(sub, current_file, depth + 1)
                    # Merge properties + required lists
                    for k, v in resolved.items():
                        if k == "properties" and "properties" in merged:
                            merged["properties"].update(v)
                        elif k == "required" and "required" in merged:
                            existing = merged["required"]
                            merged["required"] = list(set(existing + v))
                        else:
                            merged[k] = v
                # Don't process the rest of the schema after combiner handling
                remaining = {k: v for k, v in schema.items() if k != combiner}
                merged.update(remaining)
                return merged

        return schema

    def _resolve_ref(self, ref: str, current_file: str, depth: int) -> dict:
        """Resolve a $ref string, handling both same-file and cross-file refs."""
        if ref.startswith("#"):
            # Same-file ref: #/components/schemas/Foo
            raw = self._load_file(current_file)
            node = self._follow_json_pointer(raw, ref[2:])
            return self._deref(node, current_file, depth + 1)

        # Cross-file ref: TS29571_CommonData.yaml#/components/schemas/Bar
        if "#" in ref:
            file_part, pointer_part = ref.split("#", 1)
        else:
            file_part, pointer_part = ref, ""

        # Strip relative path prefix ./
        file_part = file_part.lstrip("./")
        raw = self._load_file(file_part)
        if not raw:
            return {}
        if pointer_part:
            node = self._follow_json_pointer(raw, pointer_part.lstrip("/"))
        else:
            node = raw
        return self._deref(node, file_part, depth + 1)

    def _resolve_path_item(self, path_item: Any, current_file: str):
        """Resolve a path-item-level $ref → (path_item_dict, source_file).

        3GPP aggregator specs define paths as bare $refs into a data spec, e.g.
            /subscription-data/{ueId}/…:
              $ref: 'TS29505_Subscription_Data.yaml#/paths/~1subscription-data~1%7BueId%7D…'
        Returns the *raw* target path-item (operations intact, not deref'd) plus
        the file it lives in, so operation-internal $refs resolve correctly.
        """
        if not (isinstance(path_item, dict) and "$ref" in path_item):
            return path_item, current_file
        ref = path_item["$ref"]
        if ref.startswith("#"):
            raw = self._load_file(current_file)
            return self._follow_json_pointer(raw, ref[2:].lstrip("/")), current_file
        file_part, _, pointer = ref.partition("#")
        file_part = file_part.lstrip("./")
        raw = self._load_file(file_part)
        if not raw:
            return {}, current_file
        return self._follow_json_pointer(raw, pointer.lstrip("/")), file_part

    @staticmethod
    def _follow_json_pointer(obj: dict, pointer: str) -> Any:
        """Walk obj via a slash-separated JSON pointer string."""
        from urllib.parse import unquote
        for part in pointer.split("/"):
            if not part:
                continue
            # JSON-pointer unescaping (~1→/, ~0→~) then URL-decoding: 3GPP path-item
            # refs percent-encode braces (%7B→{, %7D→}) inside the pointer.
            part = part.replace("~1", "/").replace("~0", "~")
            part = unquote(part)
            if isinstance(obj, dict):
                obj = obj.get(part, {})
            else:
                return {}
        return obj

    # ── Parameter parsing ─────────────────────────────────────────────────────

    def _parse_params(self, params: list, in_: str,
                      current_file: str, components: dict) -> list[FieldSchema]:
        result: list[FieldSchema] = []
        seen: set[str] = set()
        for p in params:
            resolved = self._deref(p, current_file)
            if resolved.get("in") != in_:
                continue
            name = resolved.get("name", "")
            if name in seen:
                continue
            seen.add(name)
            schema = self._deref(resolved.get("schema", {}), current_file)
            result.append(self._schema_to_field(
                name=name,
                schema=schema,
                required=resolved.get("required", False),
            ))
        return result

    # ── Request body extraction ───────────────────────────────────────────────

    def _resolve_request_body(self, op: dict, current_file: str,
                               components: dict) -> dict:
        rb = op.get("requestBody", {})
        if isinstance(rb, dict) and "$ref" in rb:
            rb = self._deref(rb, current_file)
        content = rb.get("content", {})
        # Prefer application/json; fall back to multipart/related
        for mime in ("application/json", "multipart/related",
                     "application/problem+json"):
            if mime in content:
                schema = content[mime].get("schema", {})
                return self._deref(schema, current_file)
        return {}

    # ── Schema flattening ─────────────────────────────────────────────────────

    def _flatten_body(self, schema: dict, current_file: str,
                       components: dict
                       ) -> tuple[list[FieldSchema], list[str], list[str]]:
        """Extract top-level properties from a body schema."""
        if not schema:
            return [], [], []
        schema = self._deref(schema, current_file)
        props: dict = schema.get("properties", {})
        required_names: list[str] = schema.get("required", [])
        fields: list[FieldSchema] = []
        for name, prop in props.items():
            resolved = self._deref(prop, current_file)
            fs = self._schema_to_field(
                name=name,
                schema=resolved,
                required=(name in required_names),
            )
            fields.append(fs)
        optional = [f.name for f in fields if not f.required]
        return fields, list(required_names), optional

    # ── Schema → FieldSchema ──────────────────────────────────────────────────

    @staticmethod
    def _schema_to_field(name: str, schema: dict, required: bool) -> FieldSchema:
        """Convert a resolved JSON Schema dict into a FieldSchema."""
        # Determine primary type (may be list in OpenAPI 3.1)
        raw_type = schema.get("type", "string")
        if isinstance(raw_type, list):
            raw_type = next((t for t in raw_type if t != "null"), "string")

        # Array item schema
        items = schema.get("items", {})
        items_type = items.get("type", "") if isinstance(items, dict) else ""
        items_format = items.get("format", "") if isinstance(items, dict) else ""
        items_enum = items.get("enum", []) if isinstance(items, dict) else []

        return FieldSchema(
            name=name,
            type=raw_type,
            format=schema.get("format", ""),
            description=schema.get("description", ""),
            enum=schema.get("enum", []),
            min_length=schema.get("minLength", 0),
            max_length=schema.get("maxLength", 0),
            min_items=schema.get("minItems", 0),
            max_items=schema.get("maxItems", 0),
            minimum=schema.get("minimum"),
            maximum=schema.get("maximum"),
            pattern=schema.get("pattern", ""),
            required=required,
            nullable=schema.get("nullable", False),
            read_only=schema.get("readOnly", False),
            write_only=schema.get("writeOnly", False),
            items_type=items_type,
            items_format=items_format,
            items_enum=items_enum,
        )

    # ── Producer-consumer dependency inference ────────────────────────────────

    @staticmethod
    def _infer_depends_on(path: str, method: str, raw_spec: dict) -> list[str]:
        """
        Infer which operations must precede this one (FivGeeFuzz / RESTler style).

        Rule: if a path has a parameter segment (e.g. /sm-contexts/{smContextRef}),
        then the POST/PUT to the parent collection (/sm-contexts) is a prerequisite
        for GET/PATCH/DELETE on the child.
        """
        if method in ("get", "patch", "delete") and "{" in path:
            parent = path.rsplit("/", 1)[0]
            # Find a POST or PUT operation on the parent path
            for op_path, item in raw_spec.get("paths", {}).items():
                if op_path == parent:
                    for m in ("post", "put"):
                        if m in item and isinstance(item[m], dict):
                            op_id = item[m].get("operationId", "")
                            if op_id:
                                return [op_id]
        return []
