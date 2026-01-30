/*
 * fuzz_dicom.h
 *
 * Generic DICOM fuzzing API with external dictionary support.
 * Provides multiple fuzzing strategies for DICOM protocol attributes.
 */

#ifndef SRC_FORWARD_FUZZ_DICOM_H_
#define SRC_FORWARD_FUZZ_DICOM_H_

#include <stdint.h>

typedef enum {
    FUZZ_RANDOM     = 0,  /* Uniform random within type range */
    FUZZ_BOUNDARY   = 1,  /* Cycle boundary/edge values (built-in tables) */
    FUZZ_DICTIONARY = 2,  /* Cycle values from external file or built-in defaults */
    FUZZ_SEQUENTIAL = 3,  /* Increment from 0 to max */
    FUZZ_BITFLIP    = 4,  /* Flip bits in value one at a time */
} fuzz_mode_t;

/*
 * Main fuzzing API: select the next fuzz value for the given attribute
 * and apply it to the current packet.
 *
 * @param proto_id  Protocol ID (701 for DICOM)
 * @param att_id    DICOM attribute ID (1=pdu_type, 4=called_ae_title, etc.)
 * @param mode      Fuzzing strategy
 * @param seed      Per-attribute seed (0 = use global seed)
 * @return 1 on success, negative on error
 */
int fuzz_dicom_attribute(uint32_t proto_id, uint32_t att_id,
                         fuzz_mode_t mode, uint32_t seed);

/*
 * Load a dictionary from a text file for the given attribute.
 * Format: one value per line, lines starting with '#' are comments,
 * blank lines are skipped, a line containing only "" is an empty string.
 *
 * Environment variable FUZZ_DICT_<att_id> overrides the filepath.
 *
 * @param att_id    DICOM attribute ID
 * @param filepath  Path to dictionary file (may be overridden by env var)
 * @return number of entries loaded, or -1 on error
 */
int fuzz_dicom_load_dictionary(uint32_t att_id, const char *filepath);

/*
 * Initialize the fuzzing subsystem with a global seed.
 * Called automatically on first use if not called explicitly.
 *
 * @param global_seed  Seed value (0 = use time-based seed)
 */
void fuzz_dicom_init(uint32_t global_seed);

/*
 * Reset all fuzzing state and free dictionary memory.
 */
void fuzz_dicom_reset(void);

/*
 * Get the current mutation counter for an attribute.
 * Useful for logging and debugging.
 */
uint64_t fuzz_dicom_get_counter(uint32_t att_id);

#endif /* SRC_FORWARD_FUZZ_DICOM_H_ */
