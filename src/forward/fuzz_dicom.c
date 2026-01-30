/*
 * fuzz_dicom.c
 *
 * Generic DICOM fuzzing API with external dictionary support.
 * Maintains per-attribute state and supports multiple fuzzing strategies.
 */

#include "fuzz_dicom.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* Defined in forward_packet.c */
extern int replace_dicom_attribute(uint32_t proto_id, uint32_t att_id,
                                   const void *new_val, int is_string);

#define MAX_ATT_ID        25
#define MAX_DICT_ENTRIES  1024
#define MAX_DICT_LINE_LEN 256

typedef struct {
    uint64_t counter;
    uint32_t seed;
    int      initialized;
    /* Dictionary storage */
    char    *dict_entries[MAX_DICT_ENTRIES];
    int      dict_count;
    int      dict_loaded;
} fuzz_att_state_t;

static fuzz_att_state_t att_states[MAX_ATT_ID + 1];
static uint32_t g_seed = 0;
static int g_initialized = 0;

/* ------------------------------------------------------------------ */
/*  Attribute type classification                                      */
/* ------------------------------------------------------------------ */

/* Returns 1 if the attribute carries a string value */
static int is_string_attribute(uint32_t att_id)
{
    switch (att_id) {
    case 4:  /* Called AE Title */
    case 5:  /* Calling AE Title */
    case 6:  /* Application Context */
    case 15: /* Patient Name */
    case 17: /* Affected SOP Class UID */
    case 19: /* Abstract Syntax */
    case 20: /* Transfer Syntax */
        return 1;
    default:
        return 0;
    }
}

/*
 * Some string attributes use an indirect pointer convention in
 * replace_dicom_attribute: new_val is char** rather than char*.
 * This applies to attributes handled via dynamic-offset tag search.
 */
static int is_indirect_string(uint32_t att_id)
{
    switch (att_id) {
    case 15: /* Patient Name */
    case 17: /* Affected SOP Class UID */
    case 19: /* Abstract Syntax */
    case 20: /* Transfer Syntax */
        return 1;
    default:
        return 0;
    }
}

/* Max value for a numeric attribute, based on byte width */
static uint32_t get_att_max(uint32_t att_id)
{
    switch (att_id) {
    case 1: case 11: case 12:
        return 0xFF;        /* 1-byte */
    case 3: case 14: case 16: case 18: case 21:
        return 0xFFFF;      /* 2-byte */
    case 2: case 8: case 10:
        return 0xFFFFFFFF;  /* 4-byte */
    default:
        return 0xFFFF;
    }
}

/* ------------------------------------------------------------------ */
/*  Apply value helpers                                                */
/* ------------------------------------------------------------------ */

static int apply_string_value(uint32_t proto_id, uint32_t att_id,
                              const char *value)
{
    if (is_indirect_string(att_id)) {
        /* replace_dicom_attribute expects char** for these att_ids */
        return replace_dicom_attribute(proto_id, att_id, &value, 1);
    }
    /* Fixed-offset string attributes: new_val is the string directly */
    return replace_dicom_attribute(proto_id, att_id, (const void *)value, 1);
}

static int apply_numeric_value(uint32_t proto_id, uint32_t att_id,
                               uint32_t value)
{
    switch (att_id) {
    /* DIMSE dynamic-offset attributes use uint16_t */
    case 14: case 16: case 18: case 21: {
        uint16_t val16 = (uint16_t)value;
        return replace_dicom_attribute(proto_id, att_id, &val16, 0);
    }
    default: {
        /* Fixed-offset attributes use int */
        int val_int = (int)value;
        return replace_dicom_attribute(proto_id, att_id, &val_int, 0);
    }
    }
}

/* ------------------------------------------------------------------ */
/*  Simple pseudo-random number generator (LCG)                        */
/* ------------------------------------------------------------------ */

static uint32_t fuzz_rand(fuzz_att_state_t *state)
{
    state->seed = state->seed * 1103515245u + 12345u;
    return (state->seed >> 16) & 0x7FFF;
}

static uint32_t fuzz_rand32(fuzz_att_state_t *state)
{
    uint32_t hi = fuzz_rand(state);
    uint32_t lo = fuzz_rand(state);
    return (hi << 16) | lo;
}

/* ------------------------------------------------------------------ */
/*  Built-in boundary tables (numeric)                                 */
/* ------------------------------------------------------------------ */

/* PDU type (att_id 1) */
static const uint32_t boundary_pdu_type[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x7F, 0x80, 0xFF
};

/* PDU length (att_id 2) */
static const uint32_t boundary_pdu_length[] = {
    0, 1, 6, 0xFF, 0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF
};

/* Protocol version (att_id 3) */
static const uint32_t boundary_protocol_version[] = {
    0x0000, 0x0001, 0x0002, 0x7FFF, 0xFFFF
};

/* Max PDU length (att_id 8) */
static const uint32_t boundary_max_pdu_length[] = {
    0, 1, 0x4000, 0x7FFE, 0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF
};

/* PDV length (att_id 10) */
static const uint32_t boundary_pdv_length[] = {
    0, 1, 0xFF, 0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF
};

/* PDV context ID (att_id 11) */
static const uint32_t boundary_pdv_context_id[] = {
    0x00, 0x01, 0x03, 0x7F, 0xFF
};

/* PDV flags (att_id 12) */
static const uint32_t boundary_pdv_flags[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0xFF
};

/* Command field (att_id 14) — all valid DIMSE commands + edge values */
static const uint32_t boundary_command_field[] = {
    0x0001, 0x8001,  /* C-STORE-RQ, C-STORE-RSP */
    0x0020, 0x8020,  /* C-FIND-RQ, C-FIND-RSP */
    0x0010, 0x8010,  /* C-GET-RQ, C-GET-RSP */
    0x0021, 0x8021,  /* C-MOVE-RQ, C-MOVE-RSP */
    0x0030, 0x8030,  /* C-ECHO-RQ, C-ECHO-RSP */
    0x0FFF,          /* C-CANCEL */
    0x0100, 0x8100,  /* N-EVENT-REPORT-RQ, N-EVENT-REPORT-RSP */
    0x0110, 0x8110,  /* N-GET-RQ, N-GET-RSP */
    0x0120, 0x8120,  /* N-SET-RQ, N-SET-RSP */
    0x0130, 0x8130,  /* N-CREATE-RQ, N-CREATE-RSP */
    0x0140, 0x8140,  /* N-ACTION-RQ, N-ACTION-RSP */
    0x0150, 0x8150,  /* N-DELETE-RQ, N-DELETE-RSP */
    0x0000, 0xFFFF, 0xDEAD  /* edge values */
};

/* Status (att_id 16) */
static const uint32_t boundary_status[] = {
    0x0000,  /* Success */
    0xFF00,  /* Pending */
    0xFF01,  /* Pending (with warnings) */
    0xA700,  /* Out of Resources */
    0xA900,  /* Data Set does not match SOP Class */
    0xC000,  /* Cannot understand / Error */
    0xFE00,  /* Cancel */
    0xDEAD, 0xFFFF  /* edge values */
};

/* Message ID (att_id 18) */
static const uint32_t boundary_message_id[] = {
    0, 1, 0x7FFF, 0x8000, 0xFFFF
};

/* Data set type (att_id 21) */
static const uint32_t boundary_data_set_type[] = {
    0x0000, 0x0001, 0x0101, 0xAAAA, 0xFFFF
};

/* Boundary table lookup */
typedef struct {
    const uint32_t *values;
    int count;
} boundary_info_t;

static boundary_info_t get_boundary_table(uint32_t att_id)
{
    boundary_info_t info = {NULL, 0};
#define ENTRY(id, arr) case id: info.values = arr; \
        info.count = (int)(sizeof(arr)/sizeof(arr[0])); break
    switch (att_id) {
    ENTRY(1,  boundary_pdu_type);
    ENTRY(2,  boundary_pdu_length);
    ENTRY(3,  boundary_protocol_version);
    ENTRY(8,  boundary_max_pdu_length);
    ENTRY(10, boundary_pdv_length);
    ENTRY(11, boundary_pdv_context_id);
    ENTRY(12, boundary_pdv_flags);
    ENTRY(14, boundary_command_field);
    ENTRY(16, boundary_status);
    ENTRY(18, boundary_message_id);
    ENTRY(21, boundary_data_set_type);
    default: break;
    }
#undef ENTRY
    return info;
}

/* ------------------------------------------------------------------ */
/*  Built-in default dictionaries (string attributes)                  */
/* ------------------------------------------------------------------ */

static const char *default_dict_ae_title[] = {
    "DCM4CHEE",
    "CONQUESTSRV1",
    "STORESCP",
    "MYPACS",
    "VIEWER",
    "OSIRIX",
    "HOROS",
    "PACSONE",
    "DCMROUTER",
    "WORKSTATION",
    "12345678901234",
    "LOWERCASE",
    "A",
    "TOOLONGAETITLE16",
    "INVALID!@#$%",
    "WAYTOOLONGAETITLEOVER16CHARS",
    "     ",
    "ORTHANC",
    "MODALITY",
};

static const char *default_dict_sop_class_uid[] = {
    "1.2.840.10008.1.1",                  /* Verification SOP Class */
    "1.2.840.10008.5.1.4.1.2.1.1",        /* Patient Root QR Find */
    "1.2.840.10008.5.1.4.1.1.2",           /* CT Image Storage */
    "1.2.840.10008.5.1.4.1.1.7",           /* Secondary Capture */
    "9.9.999.99999.9.9.9.9.9.9",           /* Invalid OID */
    "INVALID_UID",
};

static const char *default_dict_abstract_syntax[] = {
    "1.2.840.10008.1.1",                  /* Verification */
    "1.2.840.10008.5.1.4.1.2.1.1",        /* Patient Root QR Find */
    "9.9.999.99999.9.9",                   /* Invalid OID */
    "INVALID",
};

static const char *default_dict_transfer_syntax[] = {
    "1.2.840.10008.1.2",                  /* Implicit VR Little Endian */
    "1.2.840.10008.1.2.1",                /* Explicit VR Little Endian */
    "1.2.840.10008.1.2.1.99",             /* Deflated Explicit VR LE */
    "1.2.840.10008.1.2.2",                /* Explicit VR Big Endian */
    "8.8.888.88888.8.8",                   /* Invalid OID */
    "INVALID",
};

static const char *default_dict_patient_name[] = {
    "DOE^JOHN",
    "SMITH^JANE",
    "A",
    "     ",
    "TOOLONGPN",
    "INVALID!@#",
    "X^Y^Z^W^V",
};

static void load_default_dict(uint32_t att_id, fuzz_att_state_t *state)
{
    const char **defaults = NULL;
    int count = 0;

#define DEFAULTS(arr) defaults = arr; \
        count = (int)(sizeof(arr)/sizeof(arr[0]))

    switch (att_id) {
    case 4:  /* Called AE Title */
    case 5:  /* Calling AE Title */
        DEFAULTS(default_dict_ae_title);
        break;
    case 6:  /* Application Context */
        DEFAULTS(default_dict_abstract_syntax);
        break;
    case 15: /* Patient Name */
        DEFAULTS(default_dict_patient_name);
        break;
    case 17: /* Affected SOP Class UID */
        DEFAULTS(default_dict_sop_class_uid);
        break;
    case 19: /* Abstract Syntax */
        DEFAULTS(default_dict_abstract_syntax);
        break;
    case 20: /* Transfer Syntax */
        DEFAULTS(default_dict_transfer_syntax);
        break;
    default:
        return;
    }
#undef DEFAULTS

    if (defaults && count > 0) {
        int n = (count < MAX_DICT_ENTRIES) ? count : MAX_DICT_ENTRIES;
        for (int i = 0; i < n; i++)
            state->dict_entries[i] = strdup(defaults[i]);
        state->dict_count = n;
        state->dict_loaded = 1;
    }
}

/* ------------------------------------------------------------------ */
/*  Dictionary loading                                                 */
/* ------------------------------------------------------------------ */

int fuzz_dicom_load_dictionary(uint32_t att_id, const char *filepath)
{
    if (att_id > MAX_ATT_ID)
        return -1;

    fuzz_att_state_t *state = &att_states[att_id];

    /* Free any existing entries */
    for (int i = 0; i < state->dict_count; i++) {
        free(state->dict_entries[i]);
        state->dict_entries[i] = NULL;
    }
    state->dict_count = 0;
    state->dict_loaded = 0;

    /* Check environment variable override: FUZZ_DICT_<att_id> */
    char env_name[32];
    snprintf(env_name, sizeof(env_name), "FUZZ_DICT_%u", att_id);
    const char *env_path = getenv(env_name);
    const char *path = env_path ? env_path : filepath;

    if (!path) {
        fprintf(stderr, "fuzz_dicom: no dictionary path for att_id %u\n", att_id);
        return -1;
    }

    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "fuzz_dicom: cannot open dictionary '%s' for att_id %u: ",
                path, att_id);
        perror("");
        return -1;
    }

    char line[MAX_DICT_LINE_LEN];
    int count = 0;

    while (fgets(line, sizeof(line), f) && count < MAX_DICT_ENTRIES) {
        /* Skip comment lines */
        if (line[0] == '#')
            continue;

        /* Strip trailing newline/carriage-return */
        int len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';

        /* Skip blank lines */
        if (len == 0)
            continue;

        /* Support "" as explicit empty string */
        if (len == 2 && line[0] == '"' && line[1] == '"') {
            state->dict_entries[count] = strdup("");
        } else {
            state->dict_entries[count] = strdup(line);
        }
        count++;
    }

    fclose(f);
    state->dict_count = count;
    state->dict_loaded = 1;

    fprintf(stderr, "fuzz_dicom: loaded %d entries from '%s' for att_id %u\n",
            count, path, att_id);
    return count;
}

/* Auto-load dictionary: env var > built-in defaults */
static void auto_load_dict(uint32_t att_id, fuzz_att_state_t *state)
{
    /* Check environment variable first */
    char env_name[32];
    snprintf(env_name, sizeof(env_name), "FUZZ_DICT_%u", att_id);
    const char *env_path = getenv(env_name);

    if (env_path) {
        /* fuzz_dicom_load_dictionary will pick up the env var */
        fuzz_dicom_load_dictionary(att_id, NULL);
        return;
    }

    /* Fall back to built-in defaults */
    load_default_dict(att_id, state);
}

/* ------------------------------------------------------------------ */
/*  Fuzzing mode implementations                                       */
/* ------------------------------------------------------------------ */

static int fuzz_boundary(uint32_t proto_id, uint32_t att_id,
                         fuzz_att_state_t *state)
{
    boundary_info_t info = get_boundary_table(att_id);
    if (!info.values || info.count == 0) {
        fprintf(stderr, "fuzz_dicom: no boundary table for att_id %u\n", att_id);
        return -1;
    }

    int idx = state->counter % info.count;
    state->counter++;

    return apply_numeric_value(proto_id, att_id, info.values[idx]);
}

static int fuzz_dictionary(uint32_t proto_id, uint32_t att_id,
                           fuzz_att_state_t *state)
{
    /* Auto-load if no dictionary is loaded yet */
    if (!state->dict_loaded)
        auto_load_dict(att_id, state);

    if (state->dict_count == 0) {
        fprintf(stderr, "fuzz_dicom: empty dictionary for att_id %u\n", att_id);
        return -1;
    }

    int idx = state->counter % state->dict_count;
    state->counter++;

    const char *entry = state->dict_entries[idx];

    if (is_string_attribute(att_id)) {
        return apply_string_value(proto_id, att_id, entry);
    } else {
        /* Parse string as number (supports 0x prefix for hex) */
        uint32_t val = (uint32_t)strtoul(entry, NULL, 0);
        return apply_numeric_value(proto_id, att_id, val);
    }
}

static int fuzz_random(uint32_t proto_id, uint32_t att_id,
                       fuzz_att_state_t *state)
{
    state->counter++;

    if (is_string_attribute(att_id)) {
        /* Pick random entry from dictionary if available */
        if (state->dict_loaded && state->dict_count > 0) {
            int idx = fuzz_rand(state) % state->dict_count;
            return apply_string_value(proto_id, att_id,
                                      state->dict_entries[idx]);
        }
        /* Auto-load dictionary */
        auto_load_dict(att_id, state);
        if (state->dict_loaded && state->dict_count > 0) {
            int idx = fuzz_rand(state) % state->dict_count;
            return apply_string_value(proto_id, att_id,
                                      state->dict_entries[idx]);
        }
        /* Last resort: random ASCII string */
        char buf[32];
        int len = (fuzz_rand(state) % 15) + 1;
        for (int i = 0; i < len; i++)
            buf[i] = 'A' + (fuzz_rand(state) % 26);
        buf[len] = '\0';
        return apply_string_value(proto_id, att_id, buf);
    }

    uint32_t max = get_att_max(att_id);
    uint32_t val = fuzz_rand32(state) & max;
    return apply_numeric_value(proto_id, att_id, val);
}

static int fuzz_sequential(uint32_t proto_id, uint32_t att_id,
                           fuzz_att_state_t *state)
{
    uint32_t max = get_att_max(att_id);
    uint32_t val = (uint32_t)(state->counter & max);
    state->counter++;

    if (is_string_attribute(att_id)) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%u", val);
        return apply_string_value(proto_id, att_id, buf);
    }
    return apply_numeric_value(proto_id, att_id, val);
}

static int fuzz_bitflip(uint32_t proto_id, uint32_t att_id,
                        fuzz_att_state_t *state)
{
    uint32_t max = get_att_max(att_id);
    int max_bits;
    if (max <= 0xFF)        max_bits = 8;
    else if (max <= 0xFFFF) max_bits = 16;
    else                    max_bits = 32;

    int bit = state->counter % max_bits;
    uint32_t val = (1u << bit);
    state->counter++;

    if (is_string_attribute(att_id)) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%u", val);
        return apply_string_value(proto_id, att_id, buf);
    }
    return apply_numeric_value(proto_id, att_id, val);
}

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

void fuzz_dicom_init(uint32_t seed)
{
    g_seed = seed ? seed : (uint32_t)time(NULL);
    g_initialized = 1;
    memset(att_states, 0, sizeof(att_states));
}

void fuzz_dicom_reset(void)
{
    for (int i = 0; i <= MAX_ATT_ID; i++) {
        for (int j = 0; j < att_states[i].dict_count; j++)
            free(att_states[i].dict_entries[j]);
    }
    memset(att_states, 0, sizeof(att_states));
    g_initialized = 0;
}

uint64_t fuzz_dicom_get_counter(uint32_t att_id)
{
    if (att_id > MAX_ATT_ID)
        return 0;
    return att_states[att_id].counter;
}

int fuzz_dicom_attribute(uint32_t proto_id, uint32_t att_id,
                         fuzz_mode_t mode, uint32_t seed)
{
    if (att_id > MAX_ATT_ID) {
        fprintf(stderr, "fuzz_dicom: att_id %u exceeds MAX_ATT_ID %d\n",
                att_id, MAX_ATT_ID);
        return -1;
    }

    /* Lazy global init */
    if (!g_initialized)
        fuzz_dicom_init(0);

    fuzz_att_state_t *state = &att_states[att_id];

    /* Lazy per-attribute init */
    if (!state->initialized) {
        state->seed = seed ? seed : g_seed + att_id;
        state->counter = 0;
        state->initialized = 1;
    }

    switch (mode) {
    case FUZZ_RANDOM:     return fuzz_random(proto_id, att_id, state);
    case FUZZ_BOUNDARY:   return fuzz_boundary(proto_id, att_id, state);
    case FUZZ_DICTIONARY: return fuzz_dictionary(proto_id, att_id, state);
    case FUZZ_SEQUENTIAL: return fuzz_sequential(proto_id, att_id, state);
    case FUZZ_BITFLIP:    return fuzz_bitflip(proto_id, att_id, state);
    default:
        fprintf(stderr, "fuzz_dicom: unknown mode %d\n", mode);
        return -1;
    }
}
