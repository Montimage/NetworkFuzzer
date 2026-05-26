#!/usr/bin/env python3
"""
GitHub issue scraper for open5GS, free5GC, and ella-core security intelligence.

Fetches issues (open + closed) from all repos, extracts target NFs,
vulnerable API paths, root causes, PoC payloads, affected versions, and
generates fuzzer hints that map to existing RL scenarios.

Usage
-----
    # Basic (unauthenticated, 60 req/hr):
    python scripts/scrape_issues.py

    # With token (5000 req/hr):
    python scripts/scrape_issues.py --token ghp_...

    # Output path:
    python scripts/scrape_issues.py --output fuzzer/data/issues.json

    # Limit per repo (for quick tests):
    python scripts/scrape_issues.py --max-pages 3

    # Filter ella to specific versions:
    python scripts/scrape_issues.py --ella-versions v1.10.2,v1.10.1

Environment
-----------
    GITHUB_TOKEN   — alternative to --token
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any

try:
    import requests
except ImportError:
    sys.exit("requests is not installed. Run: pip install requests")

# ---------------------------------------------------------------------------
# .env loader — reads KEY=VALUE pairs into os.environ (does not overwrite)
# ---------------------------------------------------------------------------

def _load_dotenv(path: str = ".env") -> None:
    if not os.path.isfile(path):
        return
    with open(path) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            # Strip surrounding quotes (' or ")
            val = val.strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
                val = val[1:-1]
            os.environ.setdefault(key, val)

_load_dotenv()

# ---------------------------------------------------------------------------
# Repo targets
# ---------------------------------------------------------------------------

REPOS = [
    {"owner": "open5gs",       "repo": "open5gs",  "core": "open5gs"},
    {"owner": "free5gc",       "repo": "free5gc",  "core": "free5gc"},
    {"owner": "ellanetworks",  "repo": "core",     "core": "ella"},
]

# Also scrape per-NF repos in free5GC organisation
FREE5GC_NF_REPOS = [
    "amf", "smf", "nrf", "udm", "udr", "ausf", "pcf", "upf",
]

# ---------------------------------------------------------------------------
# Recent version filters (include issues that mention these)
# ---------------------------------------------------------------------------

OPEN5GS_VERSIONS = re.compile(
    r"v2\.[67]\.\d+",           # v2.6.x, v2.7.x
    re.IGNORECASE,
)
FREE5GC_VERSIONS = re.compile(
    r"v[34]\.\d+\.\d+",         # v3.x.x, v4.x.x
    re.IGNORECASE,
)
ELLA_VERSIONS = re.compile(
    r"v1\.\d+\.\d+",            # v1.x.x
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# NF detection
# ---------------------------------------------------------------------------

NF_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AMF",   re.compile(r"\bAMF\b",   re.IGNORECASE)),
    ("SMF",   re.compile(r"\bSMF\b",   re.IGNORECASE)),
    ("UPF",   re.compile(r"\bUPF\b",   re.IGNORECASE)),
    ("NRF",   re.compile(r"\bNRF\b",   re.IGNORECASE)),
    ("UDM",   re.compile(r"\bUDM\b",   re.IGNORECASE)),
    ("UDR",   re.compile(r"\bUDR\b",   re.IGNORECASE)),
    ("AUSF",  re.compile(r"\bAUSF\b",  re.IGNORECASE)),
    ("PCF",   re.compile(r"\bPCF\b",   re.IGNORECASE)),
    ("BSF",   re.compile(r"\bBSF\b",   re.IGNORECASE)),
    ("NSSF",  re.compile(r"\bNSSF\b",  re.IGNORECASE)),
    ("SCP",   re.compile(r"\bSCP\b",   re.IGNORECASE)),
    ("SEPP",  re.compile(r"\bSEPP\b",  re.IGNORECASE)),
]

# ---------------------------------------------------------------------------
# API path extraction
# ---------------------------------------------------------------------------

# Match REST paths like /nsmf-pdusession/v1/sm-contexts/{smContextRef}
_API_PATH_RE = re.compile(
    r"(/n[a-z0-9\-]+/v\d+/[a-zA-Z0-9/_\-{}]+)",
)
# Match bare paths that look like HTTP endpoints
_BARE_PATH_RE = re.compile(
    r"(?:GET|POST|PUT|PATCH|DELETE|HEAD)\s+(/[a-zA-Z0-9/_\-{}?=&]+)",
    re.IGNORECASE,
)
# Match ella operator API paths: /api/v1/subscribers, /api/v1/bgp/peers, etc.
_ELLA_API_PATH_RE = re.compile(
    r"(/api/v\d+/[a-zA-Z0-9/_\-{}?=&]+)",
)

# ---------------------------------------------------------------------------
# Root-cause classification
# ---------------------------------------------------------------------------

ROOT_CAUSE_RULES: list[tuple[str, re.Pattern]] = [
    ("null_deref",        re.compile(r"null[\s_]?pointer|null[\s_]?deref|segfault|segmentation fault|SIGSEGV|assertion.*fail|abort", re.I)),
    ("use_after_free",    re.compile(r"use.after.free|heap.use.after|UAF", re.I)),
    ("heap_overflow",     re.compile(r"heap.overflow|buffer.overflow|stack.overflow|out.of.bounds|ASAN.*overflow|heap-buffer-overflow", re.I)),
    ("memory_leak",       re.compile(r"memory.leak|leak.*memory|LeakSanitizer|LSAN", re.I)),
    ("infinite_loop",     re.compile(r"infinite.loop|hang|deadlock|busy.loop|cpu.*100", re.I)),
    ("integer_overflow",  re.compile(r"integer.overflow|int.overflow|wrap.around|UBSan.*overflow", re.I)),
    ("format_string",     re.compile(r"format.string|printf.*%[^%]", re.I)),
    ("type_confusion",    re.compile(r"type.confusion|wrong.type|mismatched.type", re.I)),
    ("logic_error",       re.compile(r"logic.error|incorrect.state|state.machine|invalid.transition|duplicate|double.free", re.I)),
    ("missing_check",     re.compile(r"missing.check|missing.validation|unchecked|no.check|bounds.check", re.I)),
    ("injection",         re.compile(r"inject|XSS|SQL|command.inject|script.alert|<script", re.I)),
    ("crash",             re.compile(r"\bcrash\b|core.dump|process.died|killed|OOM|out.of.memory", re.I)),
    ("panic",             re.compile(r"\bpanic\b|runtime.error|fatal.error", re.I)),
    ("protocol_error",    re.compile(r"protocol.error|malformed|invalid.message|wrong.format|parse.error", re.I)),
    ("auth_bypass",       re.compile(r"auth.*bypass|authentication.*bypass|unauthenticated|unauthorized", re.I)),
    ("dos",               re.compile(r"\bDoS\b|denial.of.service|resource.exhaust|flood", re.I)),
]

# ---------------------------------------------------------------------------
# Payload / PoC extraction
# ---------------------------------------------------------------------------

# Fenced code blocks: ```lang\n...\n```
_CODE_BLOCK_RE = re.compile(r"```[a-z]*\n(.*?)```", re.DOTALL)
# Inline code spans
_INLINE_CODE_RE = re.compile(r"`([^`]{4,})`")

# Patterns that look like interesting payloads
_PAYLOAD_HEURISTIC_RE = re.compile(
    r'(\{.*?\}|<[^>]+>|0x[0-9a-fA-F]+|\\x[0-9a-fA-F]{2}|%[0-9a-fA-F]{2}|'
    r'null|NaN|Infinity|-1|4294967295|2147483647|999999999)',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Fuzzer hint mapping
# ---------------------------------------------------------------------------

# Map (nf, root_cause) → scenario suggestions and mutation hints
_HINT_MAP: list[tuple[tuple[str, ...], tuple[str, ...], list[str], list[str]]] = [
    # nf_set, root_cause_set, scenario_hints, mutation_hints
    (("SMF",), ("null_deref", "crash", "panic"),
     ["smf_fuzz_ctx_create_fields", "smf_fuzz_ctx_double_create"],
     ["null_supi", "zero_psi", "empty_dnn", "missing_mandatory_field"]),

    (("SMF",), ("logic_error", "protocol_error"),
     ["smf_fuzz_ctx_modify_after_create", "smf_fuzz_ctx_release_after_create"],
     ["out_of_order_requests", "double_create", "create_then_immediately_release"]),

    (("NRF",), ("dos", "infinite_loop", "crash"),
     ["nrf_fuzz_subscribe_flood", "nrf_fuzz_scp_array_count"],
     ["large_scp_array", "rapid_register_deregister", "subscribe_without_register"]),

    (("NRF",), ("protocol_error", "missing_check"),
     ["nrf_fuzz_register_body", "nrf_fuzz_register_malformed"],
     ["malformed_nf_profile", "wrong_nf_type", "missing_nf_instance_id"]),

    (("UDM",), ("null_deref", "crash"),
     ["udm_fuzz_smf_reg_psi_boundary", "poc_4255_udm_psi_zero"],
     ["psi_zero", "psi_boundary", "psi_max_plus_one"]),

    (("UDM",), ("logic_error",),
     ["poc_4420_udm_purgeflag"],
     ["purgeflag_double_set", "purgeflag_on_unregistered"]),

    (("UDR",), ("null_deref", "crash", "missing_check"),
     ["udr_fuzz_policy_supi_variant", "udr_fuzz_sub_supi_variant",
      "poc_4412_udr_prefix_supi", "poc_4411_udr_malformed_pei"],
     ["malformed_supi_prefix", "malformed_pei", "wrong_supi_format"]),

    (("AMF",), ("null_deref", "crash"),
     ["amf_fuzz_n1n2_after_ctx", "amf_fuzz_n1n2_no_ctx"],
     ["n1n2_without_ue_context", "n1n2_double_send"]),

    (("AMF",), ("dos", "integer_overflow"),
     ["amf_fuzz_nssai_array_count"],
     ["nssai_large_array", "nssai_zero_count", "nssai_max_count"]),

    (("AMF",), ("logic_error",),
     ["amf_fuzz_event_subscribe_after_ctx"],
     ["subscribe_before_register", "subscribe_duplicate"]),

    # Generic fallbacks
    (("SMF", "NRF", "UDM", "UDR", "AMF", "AUSF", "PCF"), ("injection",),
     [],
     ["xss_in_string_fields", "null_byte_injection", "oversized_string",
      "unicode_overlong", "json_number_overflow"]),

    (("SMF", "NRF", "UDM", "UDR", "AMF", "AUSF", "PCF"), ("heap_overflow", "use_after_free"),
     [],
     ["large_payload", "oversized_array", "nested_json_depth",
      "rapid_concurrent_requests"]),

    # --- ella-core specific ---
    # Issue #1352: AMF nil pointer deref on Registration Request with missing
    # UE Security Capability IE — directly triggerable via NGAP fuzzing.
    (("AMF",), ("null_deref", "missing_check", "crash", "panic"),
     ["ella_ngap_registration_missing_security_cap",
      "ella_ngap_registration_missing_ies",
      "amf_fuzz_ngap_reg_no_ue_security_cap"],
     ["omit_ue_security_capability", "omit_supported_codecs",
      "omit_ue_network_capability", "partial_registration_request"]),

    # Ella operator API: SQL type confusion (BGP filter UUID→int cast),
    # boundary issues in slices/policies/data-networks.
    (("AMF", "SMF", "UPF"), ("type_confusion", "logic_error", "injection"),
     ["ella_api_bgp_peer_remote_as_overflow",
      "ella_api_data_network_cidr_malformed",
      "ella_api_slice_sst_sd_boundary"],
     ["bgp_remote_as_max_plus_one", "bgp_hold_time_zero",
      "uuid_in_integer_field", "cidr_malformed", "mtu_overflow",
      "sst_boundary_255", "sd_boundary_ffffff"]),

    # Ella operator API: subscriber and slice endpoint missing-validation issues.
    (("UDM", "UDR", "AMF"), ("missing_check", "protocol_error", "crash"),
     ["ella_api_subscriber_imsi_boundary",
      "ella_api_subscriber_missing_key_fields",
      "ella_api_policy_5qi_boundary",
      "ella_api_nas_security_algo_enum"],
     ["imsi_too_short", "imsi_non_numeric", "opc_wrong_length",
      "5qi_boundary_0", "5qi_boundary_255", "arp_boundary_0", "arp_boundary_16",
      "nas_integrity_algo_unknown", "nas_cipher_algo_unknown"]),
]


def _generate_hints(nfs: list[str], root_causes: list[str]) -> dict:
    scenarios: set[str] = set()
    mutations: set[str] = set()
    for nf_set, rc_set, s_hints, m_hints in _HINT_MAP:
        nf_match = any(n in nf_set for n in nfs)
        rc_match = any(r in rc_set for r in root_causes)
        if nf_match and rc_match:
            scenarios.update(s_hints)
            mutations.update(m_hints)
    return {
        "suggested_scenarios": sorted(scenarios),
        "mutation_hints":      sorted(mutations),
    }


def _priority(root_causes: list[str], state: str) -> str:
    """Assign fuzzing priority: critical / high / medium / low."""
    critical_rc = {"null_deref", "use_after_free", "heap_overflow", "dos",
                   "auth_bypass", "integer_overflow"}
    high_rc     = {"crash", "panic", "infinite_loop", "injection"}
    if any(r in critical_rc for r in root_causes):
        return "critical"
    if any(r in high_rc for r in root_causes) or state == "open":
        return "high"
    return "medium"

# ---------------------------------------------------------------------------
# Patch completeness heuristics (for closed issues)
# ---------------------------------------------------------------------------

_INCOMPLETE_PATCH_RE = re.compile(
    r"partial.fix|incomplete.fix|bypass|still.vuln|regression|reopen|another.instance|"
    r"similar.issue|follow.up|follow-up|workaround|not.fully.fixed",
    re.IGNORECASE,
)
_PR_FIX_RE = re.compile(r"#\d+|PR\s+#?\d+|pull.request", re.IGNORECASE)


def _patch_completeness(issue: dict) -> str:
    body  = issue.get("body") or ""
    title = issue.get("title") or ""
    text  = title + " " + body

    if _INCOMPLETE_PATCH_RE.search(text):
        return "likely_incomplete"
    if issue["state"] == "closed":
        if _PR_FIX_RE.search(text):
            return "patched"
        return "closed_no_pr"
    return "open"

# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------

_GH_BASE = "https://api.github.com"


def _make_session(token: str | None) -> requests.Session:
    s = requests.Session()
    s.headers["Accept"] = "application/vnd.github+json"
    s.headers["X-GitHub-Api-Version"] = "2022-11-28"
    if token:
        s.headers["Authorization"] = f"Bearer {token}"
    s.headers["User-Agent"] = "NetworkFuzzer-issue-scraper/1.0"
    return s


def _get_page(session: requests.Session, url: str, params: dict) -> tuple[list, str | None]:
    """Fetch one page; handle 403/429 rate-limit with retry."""
    for attempt in range(5):
        resp = session.get(url, params=params, timeout=30)
        if resp.status_code == 403 and "rate limit" in resp.text.lower():
            reset_ts = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
            wait = max(reset_ts - time.time(), 1)
            print(f"  Rate-limited — waiting {int(wait)}s ...", file=sys.stderr)
            time.sleep(wait + 1)
            continue
        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", 30))
            print(f"  429 — waiting {retry_after}s ...", file=sys.stderr)
            time.sleep(retry_after + 1)
            continue
        resp.raise_for_status()
        next_url = None
        link = resp.headers.get("Link", "")
        m = re.search(r'<([^>]+)>;\s*rel="next"', link)
        if m:
            next_url = m.group(1)
        return resp.json(), next_url
    raise RuntimeError(f"Failed to fetch {url} after 5 retries")


def fetch_issues(session: requests.Session, owner: str, repo: str,
                 state: str = "all", max_pages: int = 0) -> list[dict]:
    url    = f"{_GH_BASE}/repos/{owner}/{repo}/issues"
    params = {"state": state, "per_page": 100, "sort": "updated", "direction": "desc"}
    issues = []
    page   = 0
    while url:
        page += 1
        if max_pages and page > max_pages:
            break
        print(f"  {owner}/{repo}  page {page} ...", file=sys.stderr)
        data, url = _get_page(session, url, params)
        # issues endpoint also returns pull requests; skip them
        issues.extend(i for i in data if "pull_request" not in i)
        params = {}   # next_url already has params encoded
    return issues

# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def _extract_nfs(text: str) -> list[str]:
    found = []
    for name, pat in NF_PATTERNS:
        if pat.search(text):
            found.append(name)
    return found


def _extract_api_paths(text: str) -> list[str]:
    paths: set[str] = set()
    for pat in (_API_PATH_RE, _BARE_PATH_RE, _ELLA_API_PATH_RE):
        for m in pat.finditer(text):
            p = m.group(1).rstrip(".")
            if len(p) > 3:
                paths.add(p)
    return sorted(paths)


def _extract_root_causes(text: str) -> list[str]:
    found = []
    for name, pat in ROOT_CAUSE_RULES:
        if pat.search(text):
            found.append(name)
    return found


def _extract_payloads(text: str) -> list[str]:
    payloads: list[str] = []
    for m in _CODE_BLOCK_RE.finditer(text):
        block = m.group(1).strip()
        if len(block) > 4:
            payloads.append(block[:1000])   # cap at 1 KB per block
    # also grab inline code that looks like payloads
    for m in _INLINE_CODE_RE.finditer(text):
        snippet = m.group(1).strip()
        if _PAYLOAD_HEURISTIC_RE.search(snippet) and len(snippet) < 400:
            payloads.append(snippet)
    return payloads[:10]   # max 10 payloads per issue


def _extract_versions(text: str, core: str) -> list[str]:
    if core == "open5gs":
        return list(dict.fromkeys(OPEN5GS_VERSIONS.findall(text)))
    if core == "ella":
        return list(dict.fromkeys(ELLA_VERSIONS.findall(text)))
    return list(dict.fromkeys(FREE5GC_VERSIONS.findall(text)))


def _is_version_relevant(versions: list[str], core: str,
                          version_filter: set[str] | None = None,
                          strict: bool = False) -> bool:
    """True if the issue mentions a relevant version.

    version_filter — exact set of versions to match (e.g. {'v2.7.7', 'v2.7.6'}).
                     None means use the broad default filter.
    strict         — if True, issues with no version tag are excluded when a
                     version_filter is active (instead of being kept by default).
    """
    if version_filter is not None:
        if not versions:
            return not strict   # untagged: keep unless strict mode
        return any(v in version_filter for v in versions)
    # default broad filter
    if not versions:
        return True
    if core == "open5gs":
        return any(v.startswith(("v2.6", "v2.7")) for v in versions)
    if core == "ella":
        return any(v.startswith("v1.") for v in versions)
    return any(v.startswith(("v3.", "v4.")) for v in versions)


def _extract_labels(issue: dict) -> list[str]:
    return [l["name"] for l in issue.get("labels") or []]

# ---------------------------------------------------------------------------
# Single-issue processor
# ---------------------------------------------------------------------------

def process_issue(issue: dict, core: str,
                  version_filter: set[str] | None = None,
                  strict: bool = False) -> dict | None:
    title  = issue.get("title") or ""
    body   = issue.get("body") or ""
    text   = f"{title}\n{body}"

    nfs         = _extract_nfs(text)
    api_paths   = _extract_api_paths(text)
    root_causes = _extract_root_causes(text)
    payloads    = _extract_payloads(text)
    versions    = _extract_versions(text, core)
    labels      = _extract_labels(issue)

    if not _is_version_relevant(versions, core, version_filter, strict):
        return None

    patch_status = _patch_completeness(issue)
    hints        = _generate_hints(nfs, root_causes)
    priority     = _priority(root_causes, issue["state"])

    return {
        "id":            issue["number"],
        "core":          core,
        "state":         issue["state"],
        "title":         title,
        "url":           issue.get("html_url", ""),
        "created_at":    issue.get("created_at", ""),
        "updated_at":    issue.get("updated_at", ""),
        "closed_at":     issue.get("closed_at"),
        "labels":        labels,
        "target_nfs":    nfs,
        "api_paths":     api_paths,
        "root_causes":   root_causes,
        "versions":      versions,
        "payloads":      payloads,
        "patch_status":  patch_status,
        "priority":      priority,
        "fuzzer_hints":  hints,
    }

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scrape open5GS / free5GC GitHub issues for fuzzer intelligence.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--token",     default=os.getenv("GITHUB_TOKEN", ""),
                        help="GitHub personal access token (or set GITHUB_TOKEN)")
    parser.add_argument("--output",    default="fuzzer/data/issues.json",
                        metavar="FILE", help="Output JSON file (default: fuzzer/data/issues.json)")
    parser.add_argument("--max-pages", default=0, type=int, metavar="N",
                        help="Max pages per repo (0 = all, 100 issues/page)")
    parser.add_argument("--no-nf-repos", action="store_true",
                        help="Skip free5GC per-NF repositories")
    parser.add_argument("--min-priority", default="low",
                        choices=["critical", "high", "medium", "low"],
                        help="Only include issues at or above this priority")
    parser.add_argument("--open5gs-versions", default="", metavar="VERSIONS",
                        help="Comma-separated open5GS versions to match "
                             "(e.g. v2.7.7,v2.7.6,v2.7.5). "
                             "Default: any v2.6.x or v2.7.x")
    parser.add_argument("--free5gc-versions", default="", metavar="VERSIONS",
                        help="Comma-separated free5GC versions to match "
                             "(e.g. v4.2.2,v4.2.1,v4.2.0). "
                             "Default: any v3.x or v4.x")
    parser.add_argument("--ella-versions", default="", metavar="VERSIONS",
                        help="Comma-separated ella-core versions to match "
                             "(e.g. v1.10.2,v1.10.1). "
                             "Default: any v1.x.x")
    parser.add_argument("--strict-versions", action="store_true",
                        help="Exclude issues that mention no version at all "
                             "(only applies when --open5gs-versions / "
                             "--free5gc-versions / --ella-versions are set)")
    args = parser.parse_args()

    if not args.token:
        print("WARNING: no GITHUB_TOKEN set — unauthenticated requests limited to 60/hr",
              file=sys.stderr)

    priority_rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    min_rank = priority_rank[args.min_priority]

    # Build per-core version filter sets (None = use broad default)
    def _parse_versions(s: str) -> set[str] | None:
        if not s.strip():
            return None
        return {v.strip() for v in s.split(",") if v.strip()}

    version_filters: dict[str, set[str] | None] = {
        "open5gs": _parse_versions(args.open5gs_versions),
        "free5gc":  _parse_versions(args.free5gc_versions),
        "ella":     _parse_versions(args.ella_versions),
    }
    strict = args.strict_versions

    for core, vf in version_filters.items():
        if vf is not None:
            print(f"  Version filter [{core}]: {sorted(vf)}", file=sys.stderr)

    session = _make_session(args.token or None)

    # Build full repo list
    targets = list(REPOS)
    if not args.no_nf_repos:
        for nf in FREE5GC_NF_REPOS:
            targets.append({"owner": "free5gc", "repo": nf, "core": "free5gc"})

    all_issues: list[dict] = []
    skipped_version = 0
    skipped_priority = 0

    for target in targets:
        owner = target["owner"]
        repo  = target["repo"]
        core  = target["core"]

        print(f"\nFetching {owner}/{repo} ...", file=sys.stderr)
        try:
            raw = fetch_issues(session, owner, repo, state="all",
                               max_pages=args.max_pages)
        except Exception as exc:
            # Many per-NF repos may not exist yet; warn and continue
            print(f"  WARNING: could not fetch {owner}/{repo}: {exc}", file=sys.stderr)
            continue

        print(f"  {len(raw)} issues fetched", file=sys.stderr)

        for raw_issue in raw:
            rec = process_issue(raw_issue, core,
                                version_filter=version_filters.get(core),
                                strict=strict)
            if rec is None:
                skipped_version += 1
                continue
            if priority_rank[rec["priority"]] < min_rank:
                skipped_priority += 1
                continue
            all_issues.append(rec)

    # Deduplicate by url (same issue may appear in main repo and NF sub-repo)
    seen_urls: set[str] = set()
    deduped: list[dict] = []
    for rec in all_issues:
        if rec["url"] not in seen_urls:
            seen_urls.add(rec["url"])
            deduped.append(rec)

    # Sort: priority desc, updated_at desc
    deduped.sort(key=lambda r: (
        -priority_rank[r["priority"]],
        r["updated_at"],
    ), reverse=False)
    deduped.sort(key=lambda r: -priority_rank[r["priority"]])

    # Build summary stats
    from collections import Counter
    nf_counter       = Counter()
    rc_counter       = Counter()
    scenario_counter = Counter()
    for r in deduped:
        for n in r["target_nfs"]:        nf_counter[n]  += 1
        for c in r["root_causes"]:       rc_counter[c]  += 1
        for s in r["fuzzer_hints"]["suggested_scenarios"]:
            scenario_counter[s] += 1

    output = {
        "generated_at":  datetime.now(timezone.utc).isoformat(),
        "total_issues":  len(deduped),
        "skipped": {
            "version_filtered": skipped_version,
            "priority_filtered": skipped_priority,
        },
        "summary": {
            "by_core": {
                "open5gs":  sum(1 for r in deduped if r["core"] == "open5gs"),
                "free5gc":  sum(1 for r in deduped if r["core"] == "free5gc"),
                "ella":     sum(1 for r in deduped if r["core"] == "ella"),
            },
            "by_state": {
                "open":   sum(1 for r in deduped if r["state"] == "open"),
                "closed": sum(1 for r in deduped if r["state"] == "closed"),
            },
            "by_priority": {
                "critical": sum(1 for r in deduped if r["priority"] == "critical"),
                "high":     sum(1 for r in deduped if r["priority"] == "high"),
                "medium":   sum(1 for r in deduped if r["priority"] == "medium"),
                "low":      sum(1 for r in deduped if r["priority"] == "low"),
            },
            "by_patch_status": {
                "open":                sum(1 for r in deduped if r["patch_status"] == "open"),
                "patched":             sum(1 for r in deduped if r["patch_status"] == "patched"),
                "likely_incomplete":   sum(1 for r in deduped if r["patch_status"] == "likely_incomplete"),
                "closed_no_pr":        sum(1 for r in deduped if r["patch_status"] == "closed_no_pr"),
            },
            "top_nfs":            nf_counter.most_common(10),
            "top_root_causes":    rc_counter.most_common(10),
            "top_scenarios":      scenario_counter.most_common(15),
        },
        "issues": deduped,
    }

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nWrote {len(deduped)} issues → {args.output}", file=sys.stderr)
    print(f"  open5GS:  {output['summary']['by_core']['open5gs']}", file=sys.stderr)
    print(f"  free5GC:  {output['summary']['by_core']['free5gc']}", file=sys.stderr)
    print(f"  ella:     {output['summary']['by_core']['ella']}", file=sys.stderr)
    print(f"  critical: {output['summary']['by_priority']['critical']}", file=sys.stderr)
    print(f"  high:     {output['summary']['by_priority']['high']}", file=sys.stderr)
    print(f"  likely_incomplete_patch: "
          f"{output['summary']['by_patch_status']['likely_incomplete']}", file=sys.stderr)

    # Print top scenarios for quick review
    print("\nTop suggested scenarios from issue analysis:", file=sys.stderr)
    for scen, cnt in output["summary"]["top_scenarios"]:
        print(f"  {cnt:3d}×  {scen}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
