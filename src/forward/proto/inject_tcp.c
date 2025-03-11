/*
 * inject_tcp.c
 *
 * This file implements the packet injection using TCP:
 * - Once a packet arrives, its TCP payload is forwarded using this implementation
 * So:
 * + works only with TCP packets
 * + this injector works as a TCP proxy
 *
 */

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

#include "inject_tcp.h"
#include "../../lib/mmt_lib.h"

#define MAX_PDU_SIZE 16384

struct inject_tcp_context_struct {
    int client_fd;
    uint16_t nb_copies;
    const char *host;
    uint16_t port;
};

void _tcp_connect(inject_tcp_context_t *context) {
    int conn_fd, ret;
    struct sockaddr_in servaddr = {
        .sin_family = AF_INET,
        .sin_port = htons(context->port),
        .sin_addr.s_addr = inet_addr(context->host),
    };

    conn_fd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT(conn_fd >= 0, "Cannot create TCP socket, errno %d: %s", errno, strerror(errno));

    ret = connect(conn_fd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    ASSERT(ret >= 0, "Cannot connect to %s:%d using TCP", context->host, context->port);

    context->client_fd = conn_fd;
}

inject_tcp_context_t* inject_tcp_alloc(const forward_packet_target_conf_t *conf, uint32_t nb_copies) {
    inject_tcp_context_t *context = mmt_mem_alloc_and_init_zero(sizeof(struct inject_tcp_context_struct));
    context->host = conf->host;
    context->port = conf->port;
    context->nb_copies = nb_copies;
    _tcp_connect(context);
    return context;
}

static inline void _clear_tcp_buffer_if_need(inject_tcp_context_t *context) {
    char buffer[1024];
    int ret;
    do {
        ret = recv(context->client_fd, buffer, sizeof(buffer), MSG_DONTWAIT);
    } while (ret > 0);
}

/*
// TODO: Considering max PDU size of DICOM
int inject_tcp_send_packet(inject_tcp_context_t *context, const uint8_t *packet_data, uint16_t packet_size) {
    uint16_t nb_pkt_sent = 0;
    int ret, offset = 0;

    while (offset < packet_size) {
        int chunk_size = (packet_size - offset > MAX_PDU_SIZE) ? MAX_PDU_SIZE : (packet_size - offset);
        ret = send(context->client_fd, packet_data + offset, chunk_size, 0);
        if (ret > 0) {
            nb_pkt_sent++;
            offset += ret;
        } else {
            printf("[-] Error sending packet: %s (errno %d)\n", strerror(errno), errno);
            return -1;
        }
    }
    return nb_pkt_sent;
}
*/

int inject_tcp_send_packet(inject_tcp_context_t *context, const uint8_t *packet_data, uint16_t packet_size) {
    uint16_t nb_pkt_sent = 0;
    int ret, i;

    for (i = 0; i < context->nb_copies; i++) {
        ret = send(context->client_fd, packet_data, packet_size, 0);
        if (ret > 0) {
            nb_pkt_sent++;
        } else {
	        printf("[-] Error sending packet: %s (errno %d)\n", strerror(errno), errno);
            // try to reconnect
	        close(context->client_fd);
	        _tcp_connect(context);
	    }
    }

    return nb_pkt_sent;
}

void inject_tcp_release(inject_tcp_context_t *context) {
    if (!context) return;
    close(context->client_fd);
    mmt_mem_free(context);
}
