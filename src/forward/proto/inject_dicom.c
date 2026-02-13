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

    // 3. Connect to the DICOM server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("[-] Connection failed to %s:%d: %s\n", context->host, context->port, strerror(errno));
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 4. Send A-ASSOCIATE RQ (Association Request) if enabled
    if (g_send_associate_rq && context->associate_rq != NULL) {
        bytes_sent = send(sockfd, context->associate_rq, context->associate_rq_len, 0);
        if (bytes_sent < 0) {
            perror("[-] Failed to send A-ASSOCIATE RQ");
            close(sockfd);
            exit(EXIT_FAILURE);
        }
    }

    // Assign socket to context client_fd
    context->client_fd = sockfd;
    context->shown_error = false;
}

inject_dicom_context_t* inject_dicom_alloc(const forward_packet_target_conf_t *conf, uint32_t nb_copies, const char *called_ae, const char *calling_ae) {
    inject_dicom_context_t *context = mmt_mem_alloc_and_init_zero(sizeof(struct inject_dicom_context_struct));
    context->host = conf->host;
    context->port = conf->port;
    context->nb_copies = nb_copies;
    context->total_sent_pkt = 0;
    context->total_dropped_pkt = 0;
    context->total_rejected_connections = 0;
    strcpy(context->last_error_message, "No errors");
    context->last_response_code = 0;
    context->found_patient_results = 0;

    // Initialize AE title tracking fields
    memset(context->current_calling_ae_title, 0, sizeof(context->current_calling_ae_title));
    memset(context->last_successful_ae_title, 0, sizeof(context->last_successful_ae_title));

    // Build the A-ASSOCIATE-RQ PDU with configured AE titles
    uint8_t pdu_buf[512];
    size_t pdu_len = 0;
    build_associate_rq(called_ae, calling_ae, pdu_buf, &pdu_len);
    context->associate_rq = mmt_mem_alloc_and_init_zero(pdu_len);
    memcpy(context->associate_rq, pdu_buf, pdu_len);
    context->associate_rq_len = pdu_len;

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
        if (time(NULL) - start_time > MAX_WAIT_SECONDS)
            break;

        int bytes_received = recv(context->client_fd,
                                 buffer + total_bytes_received,
                                 BUFFER_SIZE - total_bytes_received,
                                 0);

        if (bytes_received > 0) {
            total_bytes_received += bytes_received;

            // Check if we have a complete response
            if (total_bytes_received >= 6) {
                if (buffer[0] == DICOM_PDU_DATA_TF) {
                    uint32_t pdu_len = (buffer[2] << 24) | (buffer[3] << 16) |
                                      (buffer[4] << 8) | buffer[5];
                    if (total_bytes_received >= pdu_len + 6)
                        complete_response = 1;
                } else {
                    complete_response = 1;
                }
            }
        } else if (bytes_received == 0) {
            break;  // Connection closed by server
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            break;  // Actual error
        }
    }

    if (total_bytes_received > 0) {
        // Track DATA-TF patient search results
        if (buffer[0] == DICOM_PDU_DATA_TF) {
            if (total_bytes_received > 100) {
                snprintf(context->last_error_message, BUFFER_SIZE,
                         "Data transfer response received (%d bytes)", total_bytes_received);
                context->found_patient_results = 1;
            } else {
                snprintf(context->last_error_message, BUFFER_SIZE,
                         "Data transfer response received (%d bytes)", total_bytes_received);
                context->found_patient_results = 0;
            }
        }

        parse_dicom_response(context, buffer, total_bytes_received);

        // If we got an accept, save the current AE title
        if (buffer[0] == DICOM_PDU_ASSOCIATE_AC) {
            strncpy(context->last_successful_ae_title, context->current_calling_ae_title, sizeof(context->last_successful_ae_title)-1);
            context->last_successful_ae_title[sizeof(context->last_successful_ae_title)-1] = '\0';

            FILE *fp = fopen("/tmp/dicom_ae_result", "w");
            if (fp) {
                fprintf(fp, "ACCEPTED:%s\n", context->current_calling_ae_title);
                fclose(fp);
            }
        }

        return 1;
    } else if (total_bytes_received == 0) {
        strcpy(context->last_error_message, "Connection closed by server");
        return -1;
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        snprintf(context->last_error_message, BUFFER_SIZE, "Receive error: %s", strerror(errno));
        return -2;
    }

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
            pdu_buf[2] = (actual_payload >> 24) & 0xFF;
            pdu_buf[3] = (actual_payload >> 16) & 0xFF;
            pdu_buf[4] = (actual_payload >> 8)  & 0xFF;
            pdu_buf[5] =  actual_payload        & 0xFF;
            packet_data = pdu_buf;
        }
    }

    // Validate the PDU type - DICOM PDUs should start with types 01-07
    uint8_t pdu_type = 0;
    if (packet_size > 0) {
        pdu_type = packet_data[0];

        if (pdu_type < 0x01 || pdu_type > 0x07) {
            // Check for common TCP payload patterns that should be skipped
            if (pdu_type == 0xBB || pdu_type == 0xCC) {
                context->total_dropped_pkt++;
                return 0;
            }
        }

        // If this is an association request, extract the AE titles for tracking
        if (pdu_type == DICOM_PDU_ASSOCIATE_RQ && packet_size >= 42) {
            char called_ae[17] = {0};
            char calling_ae[17] = {0};
            extract_ae_titles(packet_data, called_ae, calling_ae);

            strncpy(context->current_calling_ae_title, calling_ae, sizeof(context->current_calling_ae_title)-1);
            context->current_calling_ae_title[sizeof(context->current_calling_ae_title)-1] = '\0';
        }
    }

    for (int i = 0; i < context->nb_copies; i++) {
        int retry_count = 0;
        int sent = 0;

        while (retry_count < MAX_RETRIES) {
            ret = send(context->client_fd, packet_data, packet_size, 0);

            if (ret > 0) {
                sent = 1;
                nb_pkt_sent++;
                context->total_sent_pkt++;

                int response = receive_dicom_response(context);

                if (response < 0) {
                    // Connection lost, reconnect silently
                    close(context->client_fd);
                    _dicom_connect(context);

                    if (errno == ECONNRESET) {
                        sent = 0;
                        continue;
                    }
                }

                break;
            } else {
                retry_count++;

                // Reconnect if needed
                if (errno == EPIPE || errno == ECONNRESET) {
                    close(context->client_fd);
                    _dicom_connect(context);
                    sent = 0;
                }

                usleep(100000);  // 100ms before retry
            }
        }

        if (!sent) {
            context->total_dropped_pkt++;
        }
    }

    return nb_pkt_sent;
}

void inject_dicom_release(inject_dicom_context_t *context) {
    if (!context) return;

    printf("\n========== DICOM FUZZING SUMMARY ==========\n");
    printf("[+] Packets processed: %zu, sent: %zu, dropped: %zu\n",
           context->total_pkt_to_send, context->total_sent_pkt, context->total_dropped_pkt);
    if (context->total_rejected_connections > 0)
        printf("[+] Association rejections/aborts: %zu\n", context->total_rejected_connections);
    printf("[+] Last server response: %s\n", context->last_error_message);
    printf("==========================================\n");

    // Send DICOM Association Release Request before closing
    unsigned char release_rq[] = {
        0x05, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00
    };

    send(context->client_fd, release_rq, sizeof(release_rq), 0);

    // Wait briefly for release response
    unsigned char buffer[BUFFER_SIZE];
    recv(context->client_fd, buffer, BUFFER_SIZE, 0);

    close(context->client_fd);
    mmt_mem_free(context->associate_rq);
    mmt_mem_free(context);
}