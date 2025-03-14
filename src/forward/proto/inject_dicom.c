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

#include "inject_dicom.h"
#include "../../lib/mmt_lib.h"

#define MAX_PDU_SIZE 16384
#define SERVER_IP   "192.168.126.124"  // TODO: get IP from config file
#define SERVER_PORT 4242               // Standard DICOM port
#define BUFFER_SIZE 1024
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

struct inject_dicom_context_struct {
    int client_fd;
    uint16_t nb_copies;
    const char *host;
    uint16_t port;
    bool shown_error;
    size_t total_sent_pkt;
    size_t total_pkt_to_send;
};

static inline void _clear_dicom_buffer_if_need(inject_dicom_context_t *context) {
    char buffer[1024];
    int ret;
    do {
        ret = recv(context->client_fd, buffer, sizeof(buffer), MSG_DONTWAIT);
    } while (ret > 0);
}

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

    // 2. Set up server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    // 3. Connect to the DICOM server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[-] Connection failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    printf("[+] Connected to DICOM server %s:%d\n", SERVER_IP, SERVER_PORT);

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
    _dicom_connect(context);
    return context;
}

int inject_dicom_send_packet(inject_dicom_context_t *context, const uint8_t *packet_data, uint16_t packet_size) {
    uint16_t nb_pkt_sent = 0;
    int ret;

    _clear_dicom_buffer_if_need(context);
    context->total_pkt_to_send++;

    /*for (int i = 0; i < context->nb_copies; i++) {
        ret = send(context->client_fd, packet_data, packet_size, 0);
        if (ret > 0) {
            nb_pkt_sent++;
            context->total_sent_pkt++;
            printf("[+] Injected %d-th copy of %zu-th packet (size: %d) to %s:%d\n",
                   (i + 1), context->total_pkt_to_send, packet_size, context->host, context->port);
        } else {
            perror("[-] Error injecting packet");
            return -1;
        }
    }*/
    /*
    for (int i = 0; i < context->nb_copies; i++) {
        ret = send(context->client_fd, packet_data, packet_size, 0);

        if (ret > 0) {
            nb_pkt_sent++;
            context->total_sent_pkt++;
			// clear the reception buffer for each X sending packets
			if(nb_pkt_sent % 10 == 0)
				_clear_dicom_buffer_if_need( context );
            printf("Inject successfully %d-th copy of %zu-th packet size %d to %s:%d using TCP\n",
                    (i+1), context->total_pkt_to_send, packet_size,
                    context->host, context->port);
        } else if (!context->shown_error) {
            context->shown_error = true;
            printf("[-] Error injecting packet #%zu to %s:%d: (%d) %s\n",
                    context->total_pkt_to_send, context->host, context->port,
                    errno, strerror(errno));
        }
        // reconnect if need
        if (ret <= 0) {
            if (errno == EPIPE || errno == ECONNRESET) {
                printf("Broken pipe detected. Reconnecting...\n");
                close(context->client_fd);
                _dicom_connect(context);
            }
        }
    }
    */

    for (int i = 0; i < context->nb_copies; i++) {
        int retry_count = 0;
        int sent = 0;

        while (retry_count < MAX_RETRIES) {
            ret = send(context->client_fd, packet_data, packet_size, 0);

            if (ret > 0) {
                sent = 1;  // Mark packet as successfully sent
                nb_pkt_sent++;
                context->total_sent_pkt++;

                // Clear reception buffer every 10 sent packets
                if (nb_pkt_sent % 10 == 0)
                    _clear_dicom_buffer_if_need(context);

                printf("[+] Injected %d-th copy of %zu-th packet (size: %d) to %s:%d using TCP\n",
                    (i + 1), context->total_pkt_to_send, packet_size,
                    context->host, context->port);
                break;  // Exit retry loop on success
            } else {
                retry_count++;
                printf("[-] Error injecting packet #%zu (Attempt %d/%d) to %s:%d: (%d) %s\n",
                    context->total_pkt_to_send, retry_count, MAX_RETRIES,
                    context->host, context->port, errno, strerror(errno));

                // Reconnect if needed and retry
                if (errno == EPIPE || errno == ECONNRESET) {
                    printf("[!] Broken pipe detected. Reconnecting...\n");
                    close(context->client_fd);
                    _dicom_connect(context);
                }

                // Small delay before retrying
                usleep(100000);  // Sleep 100ms before retrying
            }
        }

        // If all retries failed, log the final failure
        if (!sent) {
            printf("[X] Packet #%zu failed to inject after %d retries.\n",
                context->total_pkt_to_send, MAX_RETRIES);
        }
    }

    return nb_pkt_sent;
}

void inject_dicom_release(inject_dicom_context_t *context) {
    if (!context) return;
    close(context->client_fd);
    mmt_mem_free(context);
    printf("[+] Connection closed\n");
}