/*
 * inject_dicom.h
 */

#ifndef SRC_MODULES_SECURITY_FORWARD_PROTO_INJECT_DICOM_H_
#define SRC_MODULES_SECURITY_FORWARD_PROTO_INJECT_DICOM_H_

#include "../../engine/configure.h"
#include <stdbool.h>

// DICOM PDU Types
#define DICOM_PDU_ASSOCIATE_RQ   0x01
#define DICOM_PDU_ASSOCIATE_AC   0x02
#define DICOM_PDU_ASSOCIATE_RJ   0x03
#define DICOM_PDU_DATA_TF        0x04
#define DICOM_PDU_RELEASE_RQ     0x05
#define DICOM_PDU_RELEASE_RP     0x06
#define DICOM_PDU_ABORT          0x07

// DICOM Association Rejection Reasons
#define DICOM_REJ_PERM_NO_REASON                 1
#define DICOM_REJ_TEMP_CONGESTION                2
#define DICOM_REJ_TEMP_LOCAL_LIMIT               3
#define DICOM_REJ_PERM_CALLING_AE_NOT_RECOGNIZED 7

// Global variable to control whether to send A-ASSOCIATE-RQ
extern bool g_send_associate_rq;

// Forward declare the context struct
typedef struct inject_dicom_context_struct inject_dicom_context_t;

// Define the struct with exposed fields for tracking statistics
struct inject_dicom_context_struct {
    int client_fd;
    uint16_t nb_copies;
    const char *host;
    uint16_t port;
    bool shown_error;
    size_t total_sent_pkt;
    size_t total_pkt_to_send;
    size_t total_dropped_pkt;
    size_t total_rejected_connections;
    char last_error_message[4096]; // Use same size as BUFFER_SIZE in .c file
    int last_response_code;
    bool found_patient_results; // Flag to track if patient search results were found

    // Fields for tracking AE titles
    char current_calling_ae_title[17]; // Current AE Title being tried
    char last_successful_ae_title[17]; // The last AE Title that was accepted
};

inject_dicom_context_t* inject_dicom_alloc(const forward_packet_target_conf_t *conf, uint32_t nb_copies);
int inject_dicom_send_packet(inject_dicom_context_t *context, const uint8_t *packet_data, uint16_t packet_size);
void inject_dicom_release(inject_dicom_context_t *context);

#endif /* SRC_MODULES_SECURITY_FORWARD_PROTO_INJECT_DICOM_H_ */
