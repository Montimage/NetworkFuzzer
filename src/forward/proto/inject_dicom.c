#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>

#include "inject_dicom.h"
#include "../../lib/mmt_lib.h"
#include "../../engine/configure.h"

#define MAX_PDU_SIZE 16384
#define BUFFER_SIZE 4096
#define MAX_RETRIES 3  // Number of times to retry sending a packet
#define DEFAULT_CONFIG_FILE "./networkfuzzer.conf"

// Global variable to control whether to send A-ASSOCIATE-RQ
// Default is true (send association), can be disabled with command-line option
bool g_send_associate_rq = true;

// A-ASSOCIATE-RQ packet with exact byte values from the hex dump
const unsigned char a_associate_rq[] = {
    // PDU Type and Length
    0x01, 0x00, 0x00, 0x00, 0x01, 0x9d,
    // Protocol Version and Reserved
    0x00, 0x01, 0x00, 0x00,
    // Called AE Title (MyOrthanc)
    //0x4d, 0x79, 0x4f, 0x72, 0x74, 0x68, 0x61, 0x6e, 0x63, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    // Called AE Title (ORTHANC)
    0x4f, 0x52, 0x54, 0x48, 0x41, 0x4e, 0x43, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    // Calling AE Title (MODALITY)
    0x4d, 0x4f, 0x44, 0x41, 0x4c, 0x49, 0x54, 0x59, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    // Reserved
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // Application Context Item
    0x10, 0x00, 0x00, 0x15,
    0x31, 0x2e, 0x32, 0x2e, 0x38, 0x34, 0x30, 0x2e, 0x31, 0x30, 0x30, 0x30, 0x38, 0x2e, 0x33, 0x2e, 0x31, 0x2e, 0x31, 0x2e, 0x31,

    // First Presentation Context Item (Verification SOP Class)
    0x20, 0x00, 0x00, 0x76,
    0x01, 0x00, 0x00, 0x00,
    // Abstract Syntax
    0x30, 0x00, 0x00, 0x11,
    0x31, 0x2e, 0x32, 0x2e, 0x38, 0x34, 0x30, 0x2e, 0x31, 0x30, 0x30, 0x30, 0x38, 0x2e, 0x31, 0x2e, 0x31,
    // Transfer Syntax 1
    0x40, 0x00, 0x00, 0x11,
    0x31, 0x2e, 0x32, 0x2e, 0x38, 0x34, 0x30, 0x2e, 0x31, 0x30, 0x30, 0x30, 0x38, 0x2e, 0x31, 0x2e, 0x32,
    // Transfer Syntax 2
    0x40, 0x00, 0x00, 0x13,
    0x31, 0x2e, 0x32, 0x2e, 0x38, 0x34, 0x30, 0x2e, 0x31, 0x30, 0x30, 0x30, 0x38, 0x2e, 0x31, 0x2e, 0x32, 0x2e, 0x31,
    // Transfer Syntax 3
    0x40, 0x00, 0x00, 0x16,
    0x31, 0x2e, 0x32, 0x2e, 0x38, 0x34, 0x30, 0x2e, 0x31, 0x30, 0x30, 0x30, 0x38, 0x2e, 0x31, 0x2e, 0x32, 0x2e, 0x31, 0x2e, 0x39, 0x39,
    // Transfer Syntax 4
    0x40, 0x00, 0x00, 0x13,
    0x31, 0x2e, 0x32, 0x2e, 0x38, 0x34, 0x30, 0x2e, 0x31, 0x30, 0x30, 0x30, 0x38, 0x2e, 0x31, 0x2e, 0x32, 0x2e, 0x32,

    // Second Presentation Context Item (Patient Root Query/Retrieve Information Model - FIND)
    0x20, 0x00, 0x00, 0x80,
    0x03, 0x00, 0x00, 0x00,
    // Abstract Syntax
    0x30, 0x00, 0x00, 0x1b,
    0x31, 0x2e, 0x32, 0x2e, 0x38, 0x34, 0x30, 0x2e, 0x31, 0x30, 0x30, 0x30, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x32, 0x2e, 0x31, 0x2e, 0x31,
    // Transfer Syntax 1
    0x40, 0x00, 0x00, 0x11,
    0x31, 0x2e, 0x32, 0x2e, 0x38, 0x34, 0x30, 0x2e, 0x31, 0x30, 0x30, 0x30, 0x38, 0x2e, 0x31, 0x2e, 0x32,
    // Transfer Syntax 2
    0x40, 0x00, 0x00, 0x13,
    0x31, 0x2e, 0x32, 0x2e, 0x38, 0x34, 0x30, 0x2e, 0x31, 0x30, 0x30, 0x30, 0x38, 0x2e, 0x31, 0x2e, 0x32, 0x2e, 0x31,
    // Transfer Syntax 3
    0x40, 0x00, 0x00, 0x16,
    0x31, 0x2e, 0x32, 0x2e, 0x38, 0x34, 0x30, 0x2e, 0x31, 0x30, 0x30, 0x30, 0x38, 0x2e, 0x31, 0x2e, 0x32, 0x2e, 0x31, 0x2e, 0x39, 0x39,
    // Transfer Syntax 4
    0x40, 0x00, 0x00, 0x13,
    0x31, 0x2e, 0x32, 0x2e, 0x38, 0x34, 0x30, 0x2e, 0x31, 0x30, 0x30, 0x30, 0x38, 0x2e, 0x31, 0x2e, 0x32, 0x2e, 0x32,

    // User Info Item
    0x50, 0x00, 0x00, 0x3e,
    // Max PDU Length Item
    0x51, 0x00, 0x00, 0x04,
    0x00, 0x00, 0x3f, 0xfe,
    // Implementation Class UID Item
    0x52, 0x00, 0x00, 0x20,
    0x31, 0x2e, 0x32, 0x2e, 0x38, 0x32, 0x36, 0x2e, 0x30, 0x2e, 0x31, 0x2e, 0x33, 0x36, 0x38, 0x30, 0x30, 0x34, 0x33, 0x2e, 0x39, 0x2e, 0x33, 0x38, 0x31, 0x31, 0x2e, 0x32, 0x2e, 0x31, 0x2e, 0x30,
    // Implementation Version Name Item
    0x55, 0x00, 0x00, 0x0e,
    0x50, 0x59, 0x4e, 0x45, 0x54, 0x44, 0x49, 0x43, 0x4f, 0x4d, 0x5f, 0x32, 0x31, 0x30
};

// Extract the called AE Title from a packet
static void extract_ae_titles(const uint8_t *packet_data, char *called_ae, char *calling_ae) {
    // Assuming packet_data points to the beginning of the A-ASSOCIATE-RQ PDU
    // Called AE Title is at offset 10, Calling AE Title is at offset 26
    if (packet_data[0] == DICOM_PDU_ASSOCIATE_RQ) {
        strncpy(called_ae, (const char*)&packet_data[10], 16);
        called_ae[16] = '\0';

        strncpy(calling_ae, (const char*)&packet_data[26], 16);
        calling_ae[16] = '\0';
    } else {
        strcpy(called_ae, "Unknown");
        strcpy(calling_ae, "Unknown");
    }
}

// Parse DICOM response to get rejection details
static void parse_dicom_response(inject_dicom_context_t *context, const unsigned char *buffer, ssize_t bytes_received) {
    if (bytes_received < 2) {
        strcpy(context->last_error_message, "Response too short to determine PDU type");
        context->last_response_code = -1;
        return;
    }

    // Check if the PDU type is at the beginning of the packet
    uint8_t pdu_type = buffer[0];

    // If the first byte is 0x00, check if the PDU type is at offset 4
    if (pdu_type == 0x00 && bytes_received >= 5) {
        pdu_type = buffer[4];
        printf("[DICOM DEBUG] PDU type found at offset 4: 0x%02X\n", pdu_type);
    }

    context->last_response_code = pdu_type;

    switch(pdu_type) {
        case DICOM_PDU_ASSOCIATE_AC:
            strcpy(context->last_error_message, "Association accepted");
            break;

        case DICOM_PDU_ASSOCIATE_RJ:
            if (bytes_received >= 10) {
                // Extract rejection information
                uint8_t result = buffer[7];    // Result (1=permanent, 2=transient)
                uint8_t source = buffer[8];    // Source (1=service-user, 2=service-provider, 3=service-provider-acse)
                uint8_t reason = buffer[9];    // Reason (depends on source)

                const char *result_str = (result == 1) ? "Permanent" : "Transient";
                const char *source_str = "Unknown";
                const char *reason_str = "Unknown";

                if (source == 1) {
                    source_str = "Service User";
                    if (reason == 1) reason_str = "No reason given";
                    else if (reason == 2) reason_str = "Application context name not supported";
                    else if (reason == 3) reason_str = "Calling AE title not recognized";
                    else if (reason == 7) reason_str = "Called AE title not recognized";
                } else if (source == 2) {
                    source_str = "Service Provider";
                    if (reason == 1) reason_str = "No reason given";
                    else if (reason == 2) reason_str = "Protocol version not supported";
                } else if (source == 3) {
                    source_str = "Service Provider ACSE";
                    if (reason == 1) reason_str = "No reason given";
                    else if (reason == 2) reason_str = "Temporary congestion";
                    else if (reason == 3) reason_str = "Local limit exceeded";
                }

                snprintf(context->last_error_message, BUFFER_SIZE,
                         "Association rejected: %s/%s/%s (Result=%d, Source=%d, Reason=%d)",
                         result_str, source_str, reason_str, result, source, reason);

                // Increment rejection counter
                context->total_rejected_connections++;
            } else {
                strcpy(context->last_error_message, "Association rejected (details unavailable)");
                context->total_rejected_connections++;
            }
            break;

        case DICOM_PDU_DATA_TF:
            break;

        case DICOM_PDU_ABORT:
            strcpy(context->last_error_message, "Association aborted");
            context->total_rejected_connections++;
            break;

        case DICOM_PDU_RELEASE_RQ:
            strcpy(context->last_error_message, "Association release requested");
            break;

        case DICOM_PDU_RELEASE_RP:
            strcpy(context->last_error_message, "Association released");
            break;

        default:
            snprintf(context->last_error_message, BUFFER_SIZE, "Unknown PDU type: %d", pdu_type);
            break;
    }
}

static inline void _clear_dicom_buffer_if_need(inject_dicom_context_t *context) {
    char buffer[BUFFER_SIZE];
    int ret;
    do {
        ret = recv(context->client_fd, buffer, sizeof(buffer), MSG_DONTWAIT);
    } while (ret > 0);
}

// TODO: decide when opening a DICOM connection or only a TCP connection via socket
void _dicom_connect(inject_dicom_context_t *context) {
    int sockfd;
    struct sockaddr_in server_addr;
    unsigned char buffer[BUFFER_SIZE];
    ssize_t bytes_sent, bytes_received;

    // 1. Create a socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("[-] Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 2. Set up server address using configured host and port
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(context->port);
    if (inet_pton(AF_INET, context->host, &server_addr.sin_addr) <= 0) {
        printf("[-] Invalid address: %s\n", context->host);
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    printf("[DICOM] Connecting to server: %s:%d\n", context->host, context->port);

    // 3. Connect to the DICOM server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("[-] Connection failed: %s\n", strerror(errno));
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    printf("[DICOM] Successfully connected to DICOM server\n");

    // 4. Send A-ASSOCIATE RQ (Association Request) if enabled
    if (g_send_associate_rq) {
        bytes_sent = send(sockfd, a_associate_rq, sizeof(a_associate_rq), 0);
        if (bytes_sent < 0) {
            perror("[-] Failed to send A-ASSOCIATE RQ");
            close(sockfd);
            exit(EXIT_FAILURE);
        }
        // Only show in verbose mode
        // printf("[+] A-ASSOCIATE RQ sent (%ld bytes)\n", bytes_sent);
    }

    // Assign socket to context client_fd
    context->client_fd = sockfd;
    context->shown_error = false;
}

inject_dicom_context_t* inject_dicom_alloc(const forward_packet_target_conf_t *conf, uint32_t nb_copies) {
    inject_dicom_context_t *context = mmt_mem_alloc_and_init_zero(sizeof(struct inject_dicom_context_struct));
    context->host = conf->host;
    context->port = conf->port;
    context->nb_copies = nb_copies;
    context->total_sent_pkt = 0;
    context->total_dropped_pkt = 0;  // Initialize dropped packet counter
    context->total_rejected_connections = 0; // Initialize rejected connections counter
    strcpy(context->last_error_message, "No errors");
    context->last_response_code = 0;
    context->found_patient_results = 0; // Initialize patient search results flag

    // Initialize AE title tracking fields
    memset(context->current_calling_ae_title, 0, sizeof(context->current_calling_ae_title));
    memset(context->last_successful_ae_title, 0, sizeof(context->last_successful_ae_title));

    _dicom_connect(context);
    return context;
}

// Helper function to check for and handle DICOM responses
static int receive_dicom_response(inject_dicom_context_t *context) {
    unsigned char buffer[BUFFER_SIZE];
    int total_bytes_received = 0;
    struct timeval timeout;
    int complete_response = 0;
    time_t start_time = time(NULL);
    const int MAX_WAIT_SECONDS = 5; // Maximum time to wait for a complete response

    // Set a short timeout (100ms) to check for responses without blocking too long
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000; // 100ms

    if (setsockopt(context->client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("[-] Failed to set socket receive timeout");
    }

    memset(buffer, 0, BUFFER_SIZE);

    // Keep reading until we get a complete response or timeout
    while (!complete_response && total_bytes_received < BUFFER_SIZE) {
        // Check if we've exceeded the maximum wait time
        if (time(NULL) - start_time > MAX_WAIT_SECONDS) {
            printf("[DICOM DEBUG] Timeout waiting for complete response after %d seconds\n", MAX_WAIT_SECONDS);
            break;
        }

        int bytes_received = recv(context->client_fd,
                                 buffer + total_bytes_received,
                                 BUFFER_SIZE - total_bytes_received,
                                 0);

        if (bytes_received > 0) {
            total_bytes_received += bytes_received;

            // Check if we have a complete response
            // For DATA-TF PDUs, we need at least 6 bytes for the header
            if (total_bytes_received >= 6) {
                // If this is a DATA-TF PDU, check if we have the complete PDU
                if (buffer[0] == DICOM_PDU_DATA_TF) {
                    // Extract the PDU length from bytes 2-5 (4 bytes, big-endian)
                    uint32_t pdu_len = (buffer[2] << 24) | (buffer[3] << 16) |
                                      (buffer[4] << 8) | buffer[5];

                    printf("[DICOM DEBUG] DATA-TF PDU detected with length: %u bytes\n", pdu_len);

                    // Check if we have the complete PDU
                    if (total_bytes_received >= pdu_len + 6) {
                        complete_response = 1;
                        printf("[DICOM DEBUG] Complete DATA-TF PDU received (%d bytes)\n", total_bytes_received);
                    } else {
                        printf("[DICOM DEBUG] Incomplete DATA-TF PDU: received %d/%d bytes\n",
                               total_bytes_received, pdu_len + 6);
                    }
                } else {
                    // For other PDU types, assume we have a complete response
                    complete_response = 1;
                    printf("[DICOM DEBUG] Complete non-DATA-TF PDU received (%d bytes)\n", total_bytes_received);
                }
            }
        } else if (bytes_received == 0) {
            // Connection closed by server
            printf("[DICOM DEBUG] Connection closed by server\n");
            break;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            // An actual error occurred
            printf("[DICOM DEBUG] Error receiving data: %s\n", strerror(errno));
            break;
        }
    }

    if (total_bytes_received > 0) {
        // Print the total number of bytes received
        printf("[DICOM DEBUG] Total bytes received: %d\n", total_bytes_received);

        // Print all bytes received in hex format
        printf("[DICOM DEBUG] All bytes received (hex): ");
        for (int i = 0; i < total_bytes_received; i++) {
            printf("%02X ", buffer[i]);
            // Add a newline every 16 bytes for readability
            if ((i + 1) % 16 == 0 && i < total_bytes_received - 1) {
                printf("\n[DICOM DEBUG]                    ");
            }
        }
        printf("\n");

        // Debug: Print the first few bytes of the response
        printf("[DICOM DEBUG] Response first 8 bytes: ");
        for (int i = 0; i < (total_bytes_received < 8 ? total_bytes_received : 8); i++) {
            printf("%02X ", buffer[i]);
        }
        printf("\n");

        // For DATA-TF PDUs, we might not always get a response
        // This is normal and not an error condition
        if (buffer[0] == DICOM_PDU_DATA_TF) {
            printf("[DICOM] Received DATA-TF response\n");

            // Extract the PDU length from bytes 2-5 (4 bytes, big-endian)
            uint32_t pdu_len = (buffer[2] << 24) | (buffer[3] << 16) | (buffer[4] << 8) | buffer[5];

            printf("[DICOM DEBUG] DATA-TF PDU length: %u bytes (0x%08X)\n", pdu_len, pdu_len);

            // Determine if we got results based on total bytes received
            // If total_bytes_received > 100, we got results
            if (total_bytes_received > 100) {
                printf("[DICOM DEBUG] Patient search results found! Total response: %d bytes (threshold: 100)\n", total_bytes_received);
                snprintf(context->last_error_message, BUFFER_SIZE,
                         "Data transfer response received with patient search results (Total bytes: %d)", total_bytes_received);

                // Update the summary to indicate we found results
                context->found_patient_results = 1;
            } else {
                printf("[DICOM DEBUG] No patient search results found. Total response: %d bytes (threshold: 100)\n", total_bytes_received);
                snprintf(context->last_error_message, BUFFER_SIZE,
                         "Data transfer response received with no patient search results (Total bytes: %d)", total_bytes_received);

                // Update the summary to indicate we didn't find results
                context->found_patient_results = 0;
            }

            // Check for PDV flags
            if (total_bytes_received >= 10) {
                uint8_t pdv_flags = buffer[9];
                printf("[DICOM DEBUG] PDV flags: 0x%02X\n", pdv_flags);
            }
        }

        parse_dicom_response(context, buffer, total_bytes_received);
        printf("[DICOM] Response: %s\n", context->last_error_message);

        // If we got an accept, save the current AE title
        if (buffer[0] == DICOM_PDU_ASSOCIATE_AC) {
            // Store last successful AE title
            strncpy(context->last_successful_ae_title, context->current_calling_ae_title, sizeof(context->last_successful_ae_title)-1);
            context->last_successful_ae_title[sizeof(context->last_successful_ae_title)-1] = '\0';

            // Write to a temporary file so the rule can detect success
            FILE *fp = fopen("/tmp/dicom_ae_result", "w");
            if (fp) {
                fprintf(fp, "ACCEPTED:%s\n", context->current_calling_ae_title);
                fclose(fp);
                printf("[DICOM] Valid AE title found: '%s'\n", context->current_calling_ae_title);
            }
        }

        return 1;
    } else if (total_bytes_received == 0) {
        // Connection closed by server
        strcpy(context->last_error_message, "Connection closed by server");
        printf("[-] Connection closed by server\n");
        return -1;
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        // An actual error occurred
        snprintf(context->last_error_message, BUFFER_SIZE, "Receive error: %s", strerror(errno));
        printf("[-] Error receiving response: %s\n", strerror(errno));
        return -2;
    }

    // No response available (timeout)
    // This is normal for DATA-TF PDUs, which don't always require a response
    printf("[DICOM DEBUG] No response received within timeout period\n");
    return 0;
}

int inject_dicom_send_packet(inject_dicom_context_t *context, const uint8_t *packet_data, uint16_t packet_size) {
    uint16_t nb_pkt_sent = 0;
    int ret;

    _clear_dicom_buffer_if_need(context);
    context->total_pkt_to_send++;

    // Fix PDU length: when we send a single TCP segment, the pdu_len field in the
    // DICOM header may declare a larger size than what we actually have (the original
    // PDU was split across multiple TCP segments). Update pdu_len to match the actual
    // payload so that the receiving DPI engine can classify this as valid DICOM.
    uint8_t pdu_buf[MAX_PDU_SIZE];
    if (packet_size >= 6 && packet_size <= MAX_PDU_SIZE) {
        uint8_t ptype = packet_data[0];
        uint32_t declared_len = (packet_data[2] << 24) | (packet_data[3] << 16) |
                                (packet_data[4] << 8)  | packet_data[5];
        uint32_t actual_payload = packet_size - 6; // 6-byte DICOM PDU header
        if (ptype >= 0x01 && ptype <= 0x07 && declared_len != actual_payload) {
            memcpy(pdu_buf, packet_data, packet_size);
            // Write corrected pdu_len in big-endian
            pdu_buf[2] = (actual_payload >> 24) & 0xFF;
            pdu_buf[3] = (actual_payload >> 16) & 0xFF;
            pdu_buf[4] = (actual_payload >> 8)  & 0xFF;
            pdu_buf[5] =  actual_payload        & 0xFF;
            packet_data = pdu_buf;
            printf("[DICOM] Fixed PDU length: %u -> %u bytes\n", declared_len, actual_payload);
        }
    }

    // Debug: Print the first few bytes of the packet to diagnose PDU type issues
    printf("[DICOM DEBUG] Packet #%zu first 8 bytes: ", context->total_pkt_to_send);
    for (int i = 0; i < (packet_size < 8 ? packet_size : 8); i++) {
        printf("%02X ", packet_data[i]);
    }
    printf("\n");

    // Validate the PDU type - DICOM PDUs should start with types 01-07
    uint8_t pdu_type = 0;
    if (packet_size > 0) {
        pdu_type = packet_data[0];
        const char *pdu_type_str = "Unknown";

        // If PDU type is outside valid range (01-07), this might not be a valid DICOM PDU
        if (pdu_type < 0x01 || pdu_type > 0x07) {
            printf("[DICOM WARNING] Invalid PDU type: 0x%02X - not a valid DICOM PDU\n", pdu_type);
            printf("[DICOM WARNING] This may be raw TCP data or includes non-DICOM headers\n");

            // Check for common TCP payload patterns
            if (pdu_type == 0xBB || pdu_type == 0xCC) {
                printf("[DICOM WARNING] Detected TCP packet with 0x%02X marker - skipping to avoid protocol violation\n", pdu_type);
                context->total_dropped_pkt++;
                return 0;  // Skip this packet to avoid protocol violations
            }
        } else {
            // This is a valid PDU type - get its name
            switch (pdu_type) {
                case DICOM_PDU_ASSOCIATE_RQ: pdu_type_str = "ASSOCIATE-RQ"; break;
                case DICOM_PDU_ASSOCIATE_AC: pdu_type_str = "ASSOCIATE-AC"; break;
                case DICOM_PDU_ASSOCIATE_RJ: pdu_type_str = "ASSOCIATE-RJ"; break;
                case DICOM_PDU_DATA_TF: pdu_type_str = "DATA-TF"; break;
                case DICOM_PDU_RELEASE_RQ: pdu_type_str = "RELEASE-RQ"; break;
                case DICOM_PDU_RELEASE_RP: pdu_type_str = "RELEASE-RP"; break;
                case DICOM_PDU_ABORT: pdu_type_str = "ABORT"; break;
            }
            printf("[DICOM] Processing DICOM PDU type: %s (0x%02X)\n", pdu_type_str, pdu_type);

            // For DATA-TF PDUs, we need to check if we have an active association
            if (pdu_type == DICOM_PDU_DATA_TF) {
                // Check if we have a valid association
                if (context->last_successful_ae_title[0] == '\0') {
                    printf("[DICOM WARNING] Attempting to send DATA-TF without an active association\n");
                    printf("[DICOM WARNING] This may result in the packet being dropped by the server\n");
                }
            }
        }

        // If this is an association request, extract the AE titles
        if (pdu_type == DICOM_PDU_ASSOCIATE_RQ && packet_size >= 42) {
            char called_ae[17] = {0};
            char calling_ae[17] = {0};
            extract_ae_titles(packet_data, called_ae, calling_ae);

            // Store current AE title for tracking
            strncpy(context->current_calling_ae_title, calling_ae, sizeof(context->current_calling_ae_title)-1);
            context->current_calling_ae_title[sizeof(context->current_calling_ae_title)-1] = '\0';

            printf("[DICOM] Association request with Calling AE: '%s', Called AE: '%s'\n",
                   calling_ae, called_ae);
        }
    }

    for (int i = 0; i < context->nb_copies; i++) {
        int retry_count = 0;
        int sent = 0;

        while (retry_count < MAX_RETRIES) {
            ret = send(context->client_fd, packet_data, packet_size, 0);

            if (ret > 0) {
                sent = 1;  // Mark packet as successfully sent
                nb_pkt_sent++;
                context->total_sent_pkt++;

                // After sending, wait briefly for a response
                int response = receive_dicom_response(context);

                // If this is a DATA-TF PDU, we need to check if we got a response with patient search results
                if (pdu_type == DICOM_PDU_DATA_TF && response > 0) {
                    // The receive_dicom_response function already updates context->found_patient_results
                    // based on the PDU length of the response packet
                    if (context->found_patient_results) {
                        printf("[DICOM] Patient search results found in response to modified packet!\n");
                    } else {
                        printf("[DICOM] No patient search results found in response to modified packet.\n");
                    }
                }

                if (response < 0) {
                    // Connection issue detected, reconnect
                    printf("[DICOM] Connection issue detected, reconnecting\n");
                    close(context->client_fd);
                    _dicom_connect(context);

                    // If this was a connection reset, we should retry sending this packet
                    if (errno == ECONNRESET) {
                        sent = 0;  // Reset sent flag to try again
                        continue;  // Skip to next iteration without incrementing retry_count
                    }
                }

                break;  // Exit retry loop on success
            } else {
                retry_count++;
                printf("[DICOM] Error injecting packet #%zu (Attempt %d/%d): %s\n",
                    context->total_pkt_to_send, retry_count, MAX_RETRIES, strerror(errno));

                // Reconnect if needed and retry
                if (errno == EPIPE || errno == ECONNRESET) {
                    printf("[DICOM] Broken pipe detected. Reconnecting...\n");
                    close(context->client_fd);
                    _dicom_connect(context);
                    sent = 0;  // Reset sent flag to try again
                }

                // Small delay before retrying
                usleep(100000);  // Sleep 100ms before retrying
            }
        }

        // If all retries failed, log the final failure and increment dropped packet counter
        if (!sent) {
            printf("[DICOM] Packet #%zu failed to inject after %d retries.\n",
                context->total_pkt_to_send, MAX_RETRIES);
            context->total_dropped_pkt++;  // Increment dropped packet counter
        }
    }

    return nb_pkt_sent;
}

void inject_dicom_release(inject_dicom_context_t *context) {
    if (!context) return;

    // Print a separator for better readability
    printf("\n");
    printf("========== DICOM FUZZING SUMMARY ==========\n");

    // Report total packets sent and dropped
    printf("[+] Packets processed: %zu, successfully sent: %zu, dropped: %zu\n",
           context->total_pkt_to_send, context->total_sent_pkt, context->total_dropped_pkt);

    // Report connection status statistics
    printf("[+] Association rejections: %zu\n", context->total_rejected_connections);

    // Report last error message
    printf("[+] Last DICOM message: %s\n", context->last_error_message);

    // Report patient search results
    if (context->found_patient_results) {
        printf("[+] Patient search results were found!\n");
    } else {
        printf("[+] No patient search results were found.\n");
    }
    // Report last successful AE title
    if (context->last_successful_ae_title[0] != '\0') {
        printf("[+] FOUND WORKING AE TITLE: '%s'\n", context->last_successful_ae_title);
        printf("[+] Use this AE title for future DICOM connections\n");
    } else {
        printf("[-] No valid AE title was found during fuzzing\n");
    }

    printf("==========================================\n\n");

    // Send DICOM Association Release Request before closing
    unsigned char release_rq[] = {
        0x05, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00
    };

    send(context->client_fd, release_rq, sizeof(release_rq), 0);

    // Wait briefly for release response
    unsigned char buffer[BUFFER_SIZE];
    recv(context->client_fd, buffer, BUFFER_SIZE, 0);

    close(context->client_fd);
    mmt_mem_free(context);
}