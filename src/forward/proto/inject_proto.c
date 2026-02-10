/*
 * inject_proto.c
 *
 *  Created on: May 14, 2021
 *      Author: nhnghia
 */

#include <mmt_core.h>
#include <tcpip/mmt_tcpip.h>
#include "../../lib/mmt_lib.h"
#include "inject_proto.h"

inject_proto_context_t* inject_proto_alloc( const config_t *config ){
	inject_proto_context_t *context = mmt_mem_alloc_and_init_zero( sizeof( inject_proto_context_t ));
	const forward_packet_conf_t *conf = config->forward;
	int i;
	const forward_packet_target_conf_t *target;

	for( i=0; i<conf->target_size; i++ ){
		target = & conf->targets[i];
		switch( target->protocol ){
		case FORWARD_PACKET_PROTO_SCTP:
			context->sctp = inject_sctp_alloc(target, conf->nb_copies, config->forward->bind_ip );
			break;
		case FORWARD_PACKET_PROTO_UDP:
			context->udp = inject_udp_alloc(target, conf->nb_copies );
			break;

		case FORWARD_PACKET_PROTO_HTTP2:
			context->http2 = inject_http2_alloc(target, conf->nb_copies );
			break;

		case FORWARD_PACKET_PROTO_TCP:
			context->tcp = inject_tcp_alloc(target, conf->nb_copies );
			break;

		case FORWARD_PACKET_PROTO_DICOM:
			context->dicom = inject_dicom_alloc(target, conf->nb_copies );
			break;

		default:
			ABORT("Does not support forwarding using a protocol to %s:%d", target->host, target->port );
		}
	}

	return context;
}

struct sctp_datahdr {
        uint8_t type;
        uint8_t flags;
        uint16_t length;
        uint32_t tsn;
        uint16_t stream;
        uint16_t ssn;
        uint32_t ppid;
        //uint8_t payload[0];
    };

//keep only SCTP payload in context->packet_data
static inline int _get_sctp_data_offset( const ipacket_t *ipacket ){
	int sctp_index = get_protocol_index_by_id( ipacket, PROTO_SCTP_DATA );
	//not found SCTP
	if( sctp_index == -1 )
		return -1;
	//offset of sctp in packet
	return get_packet_offset_at_index(ipacket, sctp_index) + sizeof( struct sctp_datahdr );
}

static inline int _get_udp_data_offset( const ipacket_t *ipacket ){
	int index = get_protocol_index_by_id( ipacket, PROTO_UDP );
	//not found SCTP
	if( index == -1 )
		return -1;
	//offset of sctp in packet
	return get_packet_offset_at_index(ipacket, index) + 8; //8 bytes of UDP header ( each 2 bytes: src, dst port, length, checksum)
}


static inline int _get_http2_data_offset( const ipacket_t *ipacket ){
	int index = get_protocol_index_by_id( ipacket, PROTO_HTTP2 );
	//not found Http
	if( index == -1 )
		return -1;
	//offset of sctp in packet
	return get_packet_offset_at_index(ipacket, index) ;
}

static inline int _get_tcp_data_offset( const ipacket_t *ipacket ){
	int index = get_protocol_index_by_id( ipacket, PROTO_TCP );
	//not found TCP
	if( index == -1 )
		return -1;
	//offset of tcp in packet
	return get_packet_offset_at_index(ipacket, index) + 32; //32 bytes of TCP header (TODO: better approach?)
}

static inline int _get_dicom_data_offset(const ipacket_t *ipacket) {
    int index = get_protocol_index_by_id(ipacket, PROTO_TCP);
    // not found TCP (DICOM runs over TCP)
    if (index == -1)
        return -1;

    // Get the TCP header offset
    int tcp_offset = get_packet_offset_at_index(ipacket, index);

    // Get TCP header length - this is in the 12th byte of the TCP header
    // The value is the high 4 bits, multiplied by 4
    uint8_t tcp_header_len_byte = *(uint8_t*)((uint8_t*)ipacket->data + tcp_offset + 12);
    int tcp_header_len = ((tcp_header_len_byte >> 4) & 0x0F) * 4;

    // Calculate the offset to the TCP payload (which contains the DICOM PDU)
    int payload_offset = tcp_offset + tcp_header_len;

    // Ensure we have enough data to check for a valid DICOM PDU
    if (ipacket->p_hdr->caplen <= payload_offset + 1)
        return -1;

    // Get the first byte of the payload - this should be the DICOM PDU type (01-07)
    uint8_t pdu_type = *(uint8_t*)((uint8_t*)ipacket->data + payload_offset);

    // Validate the PDU type (01-07 are valid DICOM PDU types)
    if (pdu_type >= 0x01 && pdu_type <= 0x07)
        return payload_offset;

    return -1;
}

int inject_proto_send_packet(inject_proto_context_t *context, const ipacket_t *ipacket, const uint8_t *packet_data, uint16_t packet_size) {
    int offset;
    int ret = 0;

    // Only attempt DICOM if the TCP protocol is detected first
    bool has_tcp = (get_protocol_index_by_id(ipacket, PROTO_TCP) >= 0);

    //when SCTP injector is enable
    if (context->sctp) {
        offset = _get_sctp_data_offset(ipacket);
        if (offset >= 0)
            ret += inject_sctp_send_packet(context->sctp, packet_data + offset, packet_size - offset);
    }
    if (context->udp) {
        offset = _get_udp_data_offset(ipacket);
        if (offset >= 0)
            ret += inject_udp_send_packet(context->udp, packet_data + offset, packet_size - offset);
    }
    if (context->http2) {
        offset = _get_http2_data_offset(ipacket);
        if (offset >= 0)
            ret += inject_http2_send_packet(context->http2, packet_data + offset, packet_size - offset);
    }

    // Handle TCP vs DICOM: DICOM runs on top of TCP, prefer DICOM injector when available
    bool used_tcp = false;
    if (context->tcp && has_tcp) {
        offset = _get_tcp_data_offset(ipacket);
        if (offset >= 0) {
            int dicom_offset = context->dicom ? _get_dicom_data_offset(ipacket) : -1;
            if (!context->dicom || dicom_offset < 0) {
                ret += inject_tcp_send_packet(context->tcp, packet_data + offset, packet_size - offset);
                used_tcp = true;
            }
        }
    }

    // Only use DICOM if we didn't use TCP already
    if (context->dicom && has_tcp && !used_tcp) {
        offset = _get_dicom_data_offset(ipacket);
        if (offset >= 0)
            ret += inject_dicom_send_packet(context->dicom, packet_data + offset, packet_size - offset);
    }

    if (ret == 0)
        return INJECT_PROTO_NO_AVAIL;
    return ret;
}

void inject_proto_release( inject_proto_context_t *context ){
	if( context == NULL )
		return;

	// Track total dropped packets and rejected connections across all injectors
	size_t total_dropped = 0;
	size_t total_rejections = 0;

	inject_sctp_release(context->sctp);
	inject_udp_release(context->udp);
	inject_http2_release(context->http2);
	inject_tcp_release(context->tcp);

	// DICOM injector has its own tracking of dropped packets and rejections
	if (context->dicom) {
		// The total_dropped_pkt and total_rejected_connections are reported by inject_dicom_release
		total_dropped += context->dicom->total_dropped_pkt;
		total_rejections += context->dicom->total_rejected_connections;

		// The inject_dicom_release function will print its own summary
		inject_dicom_release(context->dicom);
	}

	// Log the total dropped packets when more than one injector is used
	if (context->sctp || context->udp || context->http2 || context->tcp) {
		if (total_dropped > 0) {
			printf("[!] Warning: A total of %zu packets were dropped across all injectors\n", total_dropped);
		}
		if (total_rejections > 0) {
			printf("[!] Warning: A total of %zu connection rejections occurred across all injectors\n", total_rejections);
		}
	}

	mmt_mem_free( context );
}
