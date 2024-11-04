/*
 * inject_tcp.c
 *
 *  Created on: Jul 25, 2024
 *      Author: lethycia
 *
 * This file implements the packet injection using TCP:
 * - Once a packet arrives, its TCP payload is forwarded using this implementation
 * So:
 * + work only with TCP packets
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
#include <netinet/tcp.h> // see here 
#include <arpa/inet.h>

#include "inject_tcp.h"
#include "../../lib/mmt_lib.h"

struct inject_tcp_context_struct{
	int client_fd;
	uint16_t nb_copies;
	const char* host;
	uint16_t port;
};

// void _tcp_handshake(inject_tcp_context_t *context) {
//     // Example handshake logic: send an initial message and receive a response
//     const char *initial_message = "HELLO_SERVER";
//     char response[1024];
//     int ret;

//     ret = send(context->client_fd, initial_message, strlen(initial_message), 0);
//     ASSERT(ret >= 0, "Cannot send initial handshake message to %s:%d using TCP", context->host, context->port);

//     ret = recv(context->client_fd, response, sizeof(response), 0);
//     ASSERT(ret >= 0, "Cannot receive handshake response from %s:%d using TCP", context->host, context->port);

//     printf("Received handshake response: %s\n", response);
// }

void _tcp_connect( inject_tcp_context_t *context ){
	int conn_fd, ret;
	struct sockaddr_in servaddr = {
			.sin_family = AF_INET,
			.sin_port = htons( context->port ),
			.sin_addr.s_addr = inet_addr( context->host ),
	};

	conn_fd = socket(AF_INET, SOCK_STREAM, 0);
	ASSERT( conn_fd >= 0, "Cannot create TCP socket, errno %d: %s", errno, strerror( errno ) );
	printf("----- connected to the server");

	ret = connect(conn_fd, (struct sockaddr *) &servaddr, sizeof(servaddr));
	ASSERT( ret >= 0, "Cannot connect to %s:%d using TCP", context->host, context->port );

	context->client_fd = conn_fd;
}

inject_tcp_context_t* inject_tcp_alloc( const forward_packet_target_conf_t *conf, uint32_t nb_copies ){
	inject_tcp_context_t *context = mmt_mem_alloc_and_init_zero( sizeof( struct inject_tcp_context_struct ));
	context->host      = conf->host;
	context->port      = conf->port;
	context->nb_copies = nb_copies;
	_tcp_connect( context );
	return context;
}

static inline void _clear_tcp_buffer_if_need( inject_tcp_context_t *context ){
	char buffer[1024];
	int ret;
	do {
		ret = recv( context->client_fd, buffer, sizeof( buffer), MSG_DONTWAIT );
		/*
		if (ret > 0) {
			printf("Received %d bytes data: %s\n", ret, buffer);
			fflush(stdout);
		}*/
	} while( ret > 0);
}
// diff
int inject_tcp_send_packet( inject_tcp_context_t *context, const uint8_t *packet_data, uint16_t packet_size ){
	uint16_t nb_pkt_sent = 0;
	int ret, i;
printf("packet sent %d", nb_pkt_sent);
	for( i=0; i<context->nb_copies; i++ ){
		//returns the number of bytes written on success and -1 on failure.
		ret = send( context->client_fd, packet_data, packet_size, 0 );
		if( ret > 0 )
			nb_pkt_sent ++;
	}

	//sleep(1);
	return nb_pkt_sent;
}

void inject_tcp_release( inject_tcp_context_t *context ){
	if( !context )
		return;
	close(context->client_fd);

	mmt_mem_free( context );
}