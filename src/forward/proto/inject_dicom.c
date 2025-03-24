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

#include "inject_dicom.h"
#include "../../lib/mmt_lib.h"

#define MAX_PDU_SIZE 16384
#define SERVER_IP   "192.168.126.124"  // TODO: get IP from config file
#define SERVER_PORT 4242               // Standard DICOM port
#define BUFFER_SIZE 4096
#define MAX_RETRIES 3  // Number of times to retry sending a packet

const unsigned char a_associate_rq[] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0xe1,  // PDU Type (0x01 = A-ASSOCIATE-RQ), Length (0x00E1 = 225 bytes)
    0x00, 0x01,  // Protocol version
    0x00, 0x00,  // Reserved
    'M', 'y', 'O', 'r', 't', 'h', 'a', 'n', 'c', // Called AE Title
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', // Padding
    'M', 'O', 'D', 'A', 'L', 'I', 'T', 'Y', // Calling AE Title
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', // Padding
    0x00, 0x00, 0x00, 0x00,  // Reserved
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //0x00, 0x00, 0x00, 0x00,

    0x10, 0x00, 0x00, 0x15,  // Application Context Item (0x10), Length (0x15)
    '1', '.', '2', '.', '8', '4', '0', '.', '1', '0', '0', '0', '8', '.', '3', '.', '1', '.', '1', '.', '1',

    0x20, 0x00, 0x00, 0x3e,  // Presentation Context Item (0x20), Length (0x3E)
    0x01, 0x00,  // Presentation Context ID
    0x00, 0x00,  // Reserved
    0x30, 0x00, 0x00, 0x1c,  // Abstract Syntax (0x30), Length (0x1C)
    '1', '.', '2', '.', '8', '4', '0', '.', '1', '0', '0', '0', '8', '.', '5', '.', '1', '.', '4', '.', '1', '.', '1', '.', '1', '2', '.', '1',

    0x40, 0x00, 0x00, 0x16,  // Transfer Syntax (0x40), Length (0x16)
    '1', '.', '2', '.', '8', '4', '0', '.', '1', '0', '0', '0', '8', '.', '1', '.', '2', '.', '4', '.', '5', '0',

    0x50, 0x00, 0x00, 0x3e,  // Presentation Context Item
    0x51, 0x00, 0x00, 0x04,  // User Info Item
    0x00, 0x00, 0x3f, 0xfe,  // Max PDU Length
    0x52, 0x00, 0x00, 0x20,  // Implementation Class UID
    '1', '.', '2', '.', '8', '2', '6', '.', '0', '.', '1', '.', '3', '6', '8', '0', '0', '4', '3', '.', '9', '.', '3', '8', '1', '1', '.', '2', '.', '1', '.', '0',

    0x55, 0x00, 0x00, 0x0e,  // Implementation Version Name
    'P', 'Y', 'N', 'E', 'T', 'D', 'I', 'C', 'O', 'M', '_', '2', '1', '0'
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

    context->last_response_code = buffer[0];

    switch(buffer[0]) {
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
            snprintf(context->last_error_message, BUFFER_SIZE, "Unknown PDU type: %d", buffer[0]);
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

    // 1. Create a socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("[-] Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 2. Set up server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);
    printf("[DICOM] Connecting to server: %s:%d\n", SERVER_IP, SERVER_PORT);

    // 3. Connect to the DICOM server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("[-] Connection failed: %s\n", strerror(errno));
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    printf("[DICOM] Successfully connected to DICOM server\n");

    /*
    // 4. Send A-ASSOCIATE RQ (Association Request)
    printf("Expected A-ASSOCIATE-RQ size: %lu bytes\n", sizeof(a_associate_rq));

    bytes_sent = send(sockfd, a_associate_rq, sizeof(a_associate_rq), 0);
    if (bytes_sent < 0) {
        perror("[-] Failed to send A-ASSOCIATE RQ");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    printf("[+] A-ASSOCIATE RQ sent (%ld bytes)\n", bytes_sent);

    // 5. Wait for A-ASSOCIATE AC (Association Accept)
    bytes_received = recv(sockfd, buffer, BUFFER_SIZE, 0);
    if (bytes_received < 0) {
        perror("[-] Failed to receive A-ASSOCIATE AC");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 6. Check if it's an A-ASSOCIATE AC
    if (buffer[0] == 0x02) {
        printf("[+] Received A-ASSOCIATE AC (%ld bytes)\n", bytes_received);
    } else {
        printf("[-] Unexpected response received\n");
    }
    */

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

    // Initialize AE title tracking fields
    memset(context->current_calling_ae_title, 0, sizeof(context->current_calling_ae_title));
    memset(context->last_successful_ae_title, 0, sizeof(context->last_successful_ae_title));

    _dicom_connect(context);
    return context;
}

// Helper function to check for and handle DICOM responses
static int receive_dicom_response(inject_dicom_context_t *context) {
    unsigned char buffer[BUFFER_SIZE];
    int bytes_received;
    struct timeval timeout;

    // Set a short timeout (100ms) to check for responses without blocking too long
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000; // 100ms

    if (setsockopt(context->client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("[-] Failed to set socket receive timeout");
    }

    memset(buffer, 0, BUFFER_SIZE);
    bytes_received = recv(context->client_fd, buffer, BUFFER_SIZE, 0);

    if (bytes_received > 0) {
        parse_dicom_response(context, buffer, bytes_received);
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
    } else if (bytes_received == 0) {
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
    return 0;
}

int inject_dicom_send_packet(inject_dicom_context_t *context, const uint8_t *packet_data, uint16_t packet_size) {
    uint16_t nb_pkt_sent = 0;
    int ret;

    _clear_dicom_buffer_if_need(context);
    context->total_pkt_to_send++;

    // If this is a DICOM PDU, extract and log the type
    if (packet_size > 0) {
        uint8_t pdu_type = packet_data[0];

        // If this is an association request, extract the AE titles
        if (pdu_type == DICOM_PDU_ASSOCIATE_RQ && packet_size >= 42) {
            char called_ae[17] = {0};
            char calling_ae[17] = {0};
            extract_ae_titles(packet_data, called_ae, calling_ae);

            // Store current AE title for tracking
            strncpy(context->current_calling_ae_title, calling_ae, sizeof(context->current_calling_ae_title)-1);
            context->current_calling_ae_title[sizeof(context->current_calling_ae_title)-1] = '\0';

            printf("[DICOM] Trying Calling AE: '%s', Called AE: '%s'\n",
                   calling_ae, called_ae);
        }
    }

    for (int i = 0; i < context->nb_copies; i++) {
        int retry_count = 0;
        int sent = 0;
        int connection_reset = 0;

        while (retry_count < MAX_RETRIES) {
            ret = send(context->client_fd, packet_data, packet_size, 0);

            if (ret > 0) {
                sent = 1;  // Mark packet as successfully sent
                nb_pkt_sent++;
                context->total_sent_pkt++;

                // After sending, wait briefly for a response
                int response = receive_dicom_response(context);

                if (response < 0) {
                    // Connection issue detected, reconnect
                    printf("[DICOM] Connection issue detected, reconnecting\n");
                    close(context->client_fd);
                    _dicom_connect(context);

                    // If this was a connection reset, we should retry sending this packet
                    if (errno == ECONNRESET) {
                        connection_reset = 1;
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
                    connection_reset = 1;
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