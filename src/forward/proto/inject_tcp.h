/*
 * inject_tcp.h
 */

#ifndef SRC_MODULES_SECURITY_FORWARD_PROTO_INJECT_TCP_H_
#define SRC_MODULES_SECURITY_FORWARD_PROTO_INJECT_TCP_H_

#include "../../engine/configure.h"

typedef struct inject_tcp_context_struct inject_tcp_context_t;

inject_tcp_context_t* inject_tcp_alloc(const forward_packet_target_conf_t *conf, uint32_t nb_copies);
int inject_tcp_send_packet(inject_tcp_context_t *context, const uint8_t *packet_data, uint16_t packet_size);
void inject_tcp_release(inject_tcp_context_t *context);

#endif /* SRC_MODULES_SECURITY_FORWARD_PROTO_INJECT_TCP_H_ */
