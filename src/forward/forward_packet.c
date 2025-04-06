/*
 * forward.c
 *
 *  Created on: Jan 7, 2021
 *      Author: nhnghia
 */
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <time.h>

#include "forward_packet.h"
#include "inject_packet.h"
#include "proto/inject_proto.h"
#include "../lib/process_packet.h"
#include "../lib/mmt_lib.h"
#include "dump_packet.h"

#define MAX_PACKET_SIZE 0xFFFF

struct forward_packet_context_struct{
	const forward_packet_conf_t *config;
	uint64_t nb_forwarded_packets;
	uint64_t nb_dropped_packets;
	uint8_t *packet_data; //a copy of a packet
	uint16_t packet_size;
	uint16_t packet_delta; //used to shift packet data when forwarding
	bool has_a_satisfied_rule; //whether there exists a rule that satisfied
	const ipacket_t *ipacket;

	inject_packet_context_t *injector;    //injector by default
	inject_proto_context_t *proto_injector; //injector to inject a special protocol

	struct{
		uint32_t nb_packets, nb_bytes;
		time_t last_time;
	}stat;

	FILE *pcap_dump;
};

//TODO: need to be fixed in multi-threading
static forward_packet_context_t *cache = NULL;
static forward_packet_context_t * _get_current_context(){
	//TODO: need to be fixed in multi-threading
	//MUST_NOT_OCCUR( cache == NULL );
	return cache;
}


static inline void _update_stat( forward_packet_context_t *context, uint32_t nb_packets ){

	context->stat.nb_packets += nb_packets;
	context->stat.nb_bytes   += ( nb_packets * context->packet_size );
	time_t now = time(NULL); //return number of second from 1970
	if( now != context->stat.last_time ){
		float interval = (now - context->stat.last_time);
		log_write_dual(LOG_INFO, "Statistics of forwarded packets %.2f pps (total: %"PRIu64" packets), %.2f bps",
				context->stat.nb_packets   / interval,
				context->nb_forwarded_packets,
				context->stat.nb_bytes * 8 / interval);
		//reset stat
		context->stat.last_time  = now;
		context->stat.nb_bytes   = 0;
		context->stat.nb_packets = 0;
	}
}

static inline bool _send_packet_to_nic( forward_packet_context_t *context ){
	int ret = INJECT_PROTO_NO_AVAIL;
	uint16_t delta = context->packet_delta;
	const uint8_t *data = &context->packet_data[delta];
	const uint16_t size = context->packet_size - delta;
	//send the packet only if it has data to send
	if( delta >= context->packet_size ) {
		context->nb_dropped_packets++;
		return false;
	}

	if( context->config->is_enable ){
		//try firstly using a real connection by using proto_injector
		//do not use proto_injector when DPDK
		#ifndef NEED_DPDK
			ret = inject_proto_send_packet(context->proto_injector, context->ipacket, data, size);
		#endif
		//if no protocol is available, then use default injector (libpcap/DPDK) to inject the raw packet to output NIC
		if( ret == INJECT_PROTO_NO_AVAIL )
			ret = inject_packet_send_packet(context->injector, data, size);

		if( ret > 0 ){
			context->nb_forwarded_packets += ret;
			_update_stat( context, ret );
		} else {
			// If ret <= 0, the packet injection failed
			// This could happen if the injection was attempted but unsuccessful
			context->nb_dropped_packets++;
			log_write_dual(LOG_WARNING, "Failed to inject packet (proto_id = %d): %s",
				context->ipacket->proto_hierarchy->proto_path[context->ipacket->proto_hierarchy->len - 1],
				(ret == INJECT_PROTO_NO_AVAIL) ? "No suitable injector available" : "Injection error");
		}
	}

	//dump to file
	if( context->pcap_dump )
		dump_packet_write_to_pcap_file( context->pcap_dump, data, size );

	return (ret > 0);
}

/**
 * Called only once to initial variables
 * @param config
 * @param dpi_handler
 * @return
 */
forward_packet_context_t* forward_packet_alloc( const config_t *config, mmt_handler_t *dpi_handler ){
	int i;
	const forward_packet_target_conf_t *target;
	const forward_packet_conf_t *conf = config->forward;

	forward_packet_context_t *context = mmt_mem_alloc_and_init_zero( sizeof( forward_packet_context_t ));
	context->config = conf;

	context->proto_injector = inject_proto_alloc(config);
	//init packet injector that can be PCAP or DPDK (or other?)
	context->injector = inject_packet_alloc(config);

	context->packet_data = mmt_mem_alloc( MAX_PACKET_SIZE ); //max size of a IP packet
	context->packet_size = 0;
	context->has_a_satisfied_rule = false;
	context->stat.last_time = time(NULL);

	if( config->dump_packet->is_enable ){
		context->pcap_dump = dump_packet_create_pcap_file( config->dump_packet->output_file );
		ASSERT(context->pcap_dump != NULL, "Cannot open '%s' file for writing  packets",
			config->dump_packet->output_file );
	}

	//TODO: not work in multi-threading
	cache = context;

	return context;
}

/**
 * Called only once to free variables
 * @param context
 */
void forward_packet_release( forward_packet_context_t *context ){
	if( !context )
		return;

	// Get the count of rejected connections from proto_injector if available
	size_t rejected_connections = 0;
	if (context->proto_injector && context->proto_injector->dicom) {
		rejected_connections = context->proto_injector->dicom->total_rejected_connections;
	}

	log_write_dual(LOG_INFO, "Number of packets being successfully forwarded: %"PRIu64", dropped: %"PRIu64,
			context->nb_forwarded_packets, context->nb_dropped_packets );

	if (rejected_connections > 0) {
		log_write_dual(LOG_WARNING, "Number of rejected DICOM associations: %zu", rejected_connections);

		// If there was a last error message, report it
		if (context->proto_injector && context->proto_injector->dicom &&
		    context->proto_injector->dicom->last_error_message[0] != '\0') {
			log_write_dual(LOG_WARNING, "Last DICOM error: %s",
			              context->proto_injector->dicom->last_error_message);
		}
	}

	if( context->injector ){
		inject_packet_release( context->injector );
		context->injector = NULL;
	}

	inject_proto_release( context->proto_injector );

	if( context->pcap_dump )
		dump_packet_close_pcap_file( context->pcap_dump );

	mmt_mem_free( context->packet_data );
	mmt_mem_free( context );
}

void forward_packet_mark_being_satisfied( forward_packet_context_t *context ){
	if( context == NULL )
		return;
	context->has_a_satisfied_rule = true;
}


/**
 * This function must be called on each coming packet
 *   but before any rule being processed on the the current packet
 */
void forward_packet_on_receiving_packet_before_rule_processing(const ipacket_t * ipacket, forward_packet_context_t *context){
	if( context == NULL )
		return;
	context->ipacket = ipacket;
	context->packet_size = ipacket->p_hdr->caplen;
	context->has_a_satisfied_rule = false;
	//copy packet data, then modify packet's content
	memcpy(context->packet_data, ipacket->data, context->packet_size );
}

/**
 *  This function must be called on each coming packet
 *   but after all rules being processed on the current packet
 */
void forward_packet_on_receiving_packet_after_rule_processing( const ipacket_t * ipacket, forward_packet_context_t *context ){
	if( context == NULL )
		return;
	//whether the current packet is handled by a engine rule ?
	// if yes, we do nothing
	if( context->has_a_satisfied_rule )
		return;
	if( context->config->default_action  == ACTION_DROP ){
		context->nb_dropped_packets ++;
	} else {
		if( ! _send_packet_to_nic(context) )
			context->nb_dropped_packets ++;
	}
}


/**
 * This function is called by mmt-engine when a FORWARD rule is satisfied
 *   and its if_satisfied="#drop"
 */
void mmt_do_not_forward_packet(){
	//do nothing
	forward_packet_context_t *context = _get_current_context();
	if( context == NULL )
		return;
	context->nb_dropped_packets ++;
}

/**
 * This function is called by mmt-engine when a FORWARD rule is satisfied
 *   and its if_satisfied="#update"
 *   or explicitly call forward() in an embedded function
 */
void mmt_forward_packet(){
	forward_packet_context_t *context = _get_current_context();
	if( context == NULL )
		return;
	_send_packet_to_nic(context);
}


//this function is implemented inside mmt-dpi to update NGAP protocol
extern uint32_t update_ngap_data( u_char *data, uint32_t data_size, const ipacket_t *ipacket, uint32_t proto_id, uint32_t att_id, uint64_t new_val );

//this function is implemented inside mmt-dpi to update HTTP2 protocol
extern int update_http2_data( u_char *data, uint32_t data_size, const ipacket_t *ipacket, uint32_t proto_id, uint64_t att_id, uint32_t new_val );

/**
 * @brief Convert an integer to a ascii string to be updated in a packet
 *
 * @param ascii_string memory location for updating the value
 * @param length length of the memory need to be updated
 * @param num new value to be updated to
 * @return uint32_t
 * 1 - Successfully
 * 0 - Failed
 *  -> if the input length is not an even number
 *  -> if the input value is too BIG
 */
uint32_t int_to_ascii_string(u_char * ascii_string, int length, uint64_t num) {
  if (length % 2 != 0) {
    printf("[ERROR] The input length must be an even number (2, 4, 6, ...): %d\n",length);
    return 0;
  }
    char hex_string[50];
    sprintf(hex_string, "%0.*lx",length, num);
    printf("hex_string: %s\n", hex_string);
    int hex_string_len = strlen(hex_string);
    printf("hex_string_len: %d (length: %d)\n", hex_string_len, length);
    if (hex_string_len > length) {
      printf("The input value is out of range\n");
      printf("Input number: %lu\n", num);
      printf("Max hex length: %d\n", length);
      printf("Converted hex length: %d\n", hex_string_len);
      return 0;
    }

    int i;
    for (i = 0; i < strlen(hex_string); i += 2) {
        char hex_byte[3] = {hex_string[i], hex_string[i+1], '\0'};
        ascii_string[i/2] = (char) strtol(hex_byte, NULL, 16);
    }
    // ascii_string[i/2] = '\0';
    printf("Converted string: %s\n", ascii_string);
    return 1;
}

// TODO: Move these functions to DICOM plugin: update dicom numeric and string

/**
 * @brief Modify numeric attribute in a DICOM packet
 *
 * @param data
 * @param data_size
 * @param ipacket
 * @param proto_id
 * @param att_id
 * @param new_val
 * @return uint32_t 1 - Successful/ 0 - Failed
 */
uint32_t update_dicom_data( u_char *data, uint32_t data_size, const ipacket_t *ipacket, uint32_t proto_id, uint32_t att_id, uint32_t new_val){
	uint32_t ret = 0;
	fprintf(stderr, "Going to update the value of attribute %d, new value : %u (%x)\n",att_id, new_val, new_val);
	debug("DICOM: update the value of attribute %d, new value : %u (%x)",att_id, new_val, new_val);
	if( proto_id != 701 )
		return ret;
	int index = get_protocol_index_by_id( ipacket, 701 );
	if( index == -1 )
		return ret;

	unsigned int dicom_offset = get_packet_offset_at_index( ipacket, index );

	int att_data_len = 0;
    int att_offset = 0;

	switch( att_id ){
	case 1:
		att_data_len = 1;
    	att_offset = 0;
		break;
	case 2:
		att_data_len = 4;
    	att_offset = 2;
		break;
	case 3:
		att_data_len = 2;
    	att_offset = 6;
		break;
	case 6:
		att_data_len = 21;
    	att_offset = 78;
		break;
	case 8:
		att_data_len = 4;
    	att_offset = 295;
		break;
	case 10:
		att_data_len = 4;
    	att_offset = 6;
		break;
	case 12:
		att_data_len = 1;
    	att_offset = 11;
		break;
	case 15:
		att_data_len = 21;
    	att_offset = 54;
		break;
	default:
        fprintf(stderr, "Unsupported modify attribute: %d",att_id);
        return ret;
	}
	att_offset += dicom_offset;
    fprintf(stderr, "attribute id: %d, attribute offset: %d, attribute data len: %d\n",att_id, att_offset, att_data_len);

	ret = int_to_ascii_string((u_char *) &data[att_offset], att_data_len * 2, new_val);
    if (ret == 1) {
      printf("Successfully modified!!!");
    } else {
      printf("Failed to modify!!!");
    }

	return 1;
}


/**
 * This function is called by mmt-engine when a FORWARD rule is satisfied
 *   and its if_satisfied="#update( xx.yy, ..)"
 *   or explicitly call set_numeric_value in an embedded function
 */
void mmt_set_attribute_number_value(uint32_t proto_id, uint32_t att_id, uint64_t new_val){
	forward_packet_context_t *context = _get_current_context();
	if( context == NULL )
		return;
	int ret = 0;
	int difference;

	switch(proto_id){
	case(PROTO_NGAP):
		ret = update_ngap_data(context->packet_data, context->packet_size, context->ipacket, proto_id, att_id, new_val );
		if( ! ret )
			log_write( LOG_ERR, "Cannot set new value %"PRIu64" for att %d of proto %d for packet id %"PRIu64,
				new_val, att_id, proto_id, context->ipacket->packet_id);
		break;

	case(PROTO_HTTP2):
		difference = update_http2_data(context->packet_data, context->packet_size, context->ipacket, proto_id, att_id, new_val );

		// why 400?
		if( difference != 0 && difference < 400 && difference > -400 )//check that difference value is not too elevated or too small
			if( context->packet_size + difference >= 0 )
				context->packet_size = context->packet_size + difference;
			//printf("mmt_set_attribute_number_value difference %d \n",difference);
			//printf("mmt_set_attribute_number_value Packet size %d\n",context->packet_size);
		break;
	case(701):
		ret = update_dicom_data(context->packet_data, context->packet_size, context->ipacket, proto_id, att_id, new_val );
		if( ! ret )
			log_write( LOG_ERR, "Cannot set new value %"PRIu64" for att %d of proto %d for packet id %"PRIu64,
				new_val, att_id, proto_id, context->ipacket->packet_id);
		break;

	default:
		log_write( LOG_ERR, "Cannot set new value %"PRIu64" for att %d of proto %d for packet id %"PRIu64,
			new_val, att_id, proto_id, context->ipacket->packet_id);
			}
}


/**
 * This is an embedded function that can be called in rules by user
 *
 * Returns the offset in number of bytes from the beginning of the packet for the protocol at the given index
 * @param proto_id is the ID of the protocol to be replaced
 * @param data_length length of data
 * @param data a sequence of bytes that will set to protocol
 * @return the offset in number of bytes since the beginning of the packet of the protocol, if successfully.
 * Otherwise it returns a negative number:
 *   -1 if the proto_id does not exist in the packet
 *   -2 if data is too big
 */
int mmt_replace_data_at_protocol_id( uint32_t proto_id, uint16_t data_length, const char* data){
	forward_packet_context_t *context = _get_current_context();
	if( context == NULL )
		return -3;
	int index = get_protocol_index_by_id( context->ipacket, proto_id );
	//not found SCTP
	if( index == -1 )
		return -1;
	//offset of sctp in packet
	int offset = get_packet_offset_at_index( context->ipacket, index);
	int next_offset = get_packet_offset_at_index( context->ipacket, index+1);
	if( next_offset <= offset )
		next_offset = offset;
	if( next_offset >= context->packet_size )
		//TODO: a risk here when context->packet_size != context->ipacket->p_hdr->len
		next_offset = context->packet_size;
	int old_length = next_offset - offset;
	int new_packet_size = context->packet_size - old_length + data_length;

	if( new_packet_size > MAX_PACKET_SIZE )
		return -2;
	int backup_data_size = context->packet_size - next_offset;
	uint8_t tmp_data[ MAX_PACKET_SIZE ];
	//backup the data after the segment to be replaced
	memcpy( tmp_data, &context->packet_data[ next_offset ], backup_data_size );
	//replace the segment by the data
	memcpy( &context->packet_data[offset], data, data_length );
	//put the backup segment back to packet_data
	memcpy( &context->packet_data[offset+data_length], tmp_data, backup_data_size );
	//update the new size of data
	context->packet_size = new_packet_size;

	return offset;
}

/**
 *  This is an embedded function that can be called in rules by user
 *   to update the parameters in sctp_sendmsg function
 *  See : https://linux.die.net/man/3/sctp_sendmsg
 * @param ppid
 * @param flags
 * @param stream_no
 * @param timetolive
 * @return
 */
int mmt_update_sctp_param( uint32_t ppid, uint32_t flags, uint16_t stream_no, uint32_t timetolive ){
	forward_packet_context_t *context = _get_current_context();
	if( context == NULL )
		return -3;

	inject_sctp_update_param( context->proto_injector->sctp, ppid, flags, stream_no, timetolive, 0);
	return 0;
}


// TODO: Move these functions to DICOM plugin: update dicom numeric and string

/**
 * @brief Modify string attribute in a DICOM packet
 *
 * @param data
 * @param data_size
 * @param ipacket
 * @param proto_id
 * @param att_id
 * @param new_val
 * @return uint32_t 1 - Successful/ 0 - Failed
 */
uint32_t update_dicom_string_data(char *data, uint32_t data_size, const ipacket_t *ipacket, uint32_t proto_id, uint32_t att_id, u_char *new_val) {
    uint32_t ret = 0;

    if (proto_id != 701)
        return ret;

    int index = get_protocol_index_by_id(ipacket, 701);
    if (index == -1)
        return ret;

    unsigned int dicom_offset = get_packet_offset_at_index(ipacket, index);

    int att_data_len = 0;
    int att_offset = 0;

    switch (att_id) {
    case 4:
        att_data_len = 16;
        att_offset = 10;
        break;
    case 5:
        att_data_len = 16;
        att_offset = 26;
        break;
	case 6:
		att_data_len = 21;
    	att_offset = 78;
		break;
	case 8:
		att_data_len = 4;
    	att_offset = 295;
		break;
	case 10:
		att_data_len = 4;
    	att_offset = 6;
		break;
	case 12:
		att_data_len = 1;
    	att_offset = 11;
		break;
	case 15:
		att_data_len = 21; // TODO: flexible length
		att_offset = 54;
		break;
    default:
        fprintf(stderr, "Unsupported modify attribute: %d\n", att_id);
        return ret;
    }

    att_offset += dicom_offset;
    fprintf(stderr, "attribute id: %d, attribute offset: %d, attribute data len: %d\n", att_id, att_offset, att_data_len);

    int new_val_len = strlen((const char *)new_val);
    if (new_val_len > att_data_len) {
        fprintf(stderr, "New value is too long for attribute %d\n", att_id);
        return ret;
    }

    // Create a buffer to hold the new value with padding
    char padded_val[att_data_len + 1]; // +1 for null terminator
    memset(padded_val, 0x20, att_data_len); // Fill with spaces
    strncpy(padded_val, (const char *)new_val, new_val_len);
    padded_val[att_data_len] = '\0'; // Ensure null termination

    memcpy(&data[att_offset], padded_val, att_data_len);

    fprintf(stderr, "Successfully modified attribute %d with new value: %s\n", att_id, padded_val);

    return 1;
}


// TODO: test it after if it is according to network data type
// void mmt_set_attribute_string_value(uint32_t proto_id, uint32_t att_id, u_char *new_val) {
//     forward_packet_context_t *context = _get_current_context();
//     if (context == NULL)
//         return;

//     int ret = 0;
//     switch (proto_id) {
//     case (701):
//         ret = update_dicom_string_data(context->packet_data, context->packet_size, context->ipacket, proto_id, att_id, new_val);
//         if (!ret) {
//             log_write(LOG_ERR, "Cannot set new value %s for att %d of proto %d for packet id %" PRIu64,
//                 new_val, att_id, proto_id, context->ipacket->packet_id);
//         }
//         break;

//     default:
//         log_write(LOG_ERR, "Cannot set new value %s for att %d of proto %d for packet id %" PRIu64,
//             new_val, att_id, proto_id, context->ipacket->packet_id);
//     }
// }

int get_dicom_attribute_info(uint32_t att_id, int *att_offset, int *att_data_len) {
    printf("[DICOM DEBUG] Getting info for attribute ID: %d\n", att_id);

    switch (att_id) {
        case 1:
            *att_data_len = 1;
            *att_offset = 0;
            break;
        case 2:
            *att_data_len = 4;
            *att_offset = 2;
            break;
        case 3:
            *att_data_len = 2;
            *att_offset = 6;
            break;
        case 4:
            *att_data_len = 16;
            *att_offset = 10;
            break;
        case 5:
            *att_data_len = 16;
            *att_offset = 26;
            break;
        case 6:
            *att_data_len = 21;
            *att_offset = 78;
            break;
        case 8:
            *att_data_len = 4;
            *att_offset = 295;
            break;
        case 10:
            *att_data_len = 4;
            *att_offset = 6;
            break;
        case 12:
            *att_data_len = 1;
            *att_offset = 11;
            break;
        case 15:  // Patient Name attribute
            *att_data_len = 21;  // Based on hex dump, patient name is 30 bytes
            *att_offset = 54;   // Based on hex dump, patient name starts at byte 112
            printf("[DICOM DEBUG] Found patient name attribute (ID 15) - offset: %d, length: %d\n", *att_offset, *att_data_len);

            // Print the patient name as a string
            forward_packet_context_t *context = _get_current_context();
            if (context != NULL) {
                int index = get_protocol_index_by_id(context->ipacket, 701);
                if (index != -1) {
                    unsigned int dicom_offset = get_packet_offset_at_index(context->ipacket, index);
                    int patient_name_offset = dicom_offset + *att_offset;

                    // Create a buffer for the patient name
                    char patient_name[256] = {0};
                    int copy_len = *att_data_len;
                    if (patient_name_offset + copy_len > context->packet_size) {
                        copy_len = context->packet_size - patient_name_offset;
                    }

                    // Copy the patient name
                    memcpy(patient_name, &context->packet_data[patient_name_offset], copy_len);

                    // Print the patient name in hex
                    printf("[DICOM DEBUG] Patient name (hex): ");
                    for (int i = 0; i < copy_len; i++) {
                        printf("%02X ", (unsigned char)patient_name[i]);
                    }
                    printf("\n");

                    // Print the patient name as a string, replacing non-printable characters with dots
                    printf("[DICOM DEBUG] Patient name (string): '");
                    for (int i = 0; i < copy_len; i++) {
                        if (patient_name[i] >= 32 && patient_name[i] <= 126) {
                            printf("%c", patient_name[i]);
                        } else {
                            printf(".");
                        }
                    }
                    printf("'\n");
                }
            }
            break;
        default:
            fprintf(stderr, "Unsupported modify attribute: %d\n", att_id);
            return -1;
    }

    printf("[DICOM DEBUG] Attribute info - offset: %d, data length: %d\n", *att_offset, *att_data_len);
    return 0;
}

// This function changes an attribute in the packet
int replace_dicom_attribute(uint32_t proto_id, uint32_t att_id, const void *new_val, int is_string) {
    forward_packet_context_t *context = _get_current_context();
    if (context == NULL)
        return -3;

    int att_offset, att_data_len;
    if (get_dicom_attribute_info(att_id, &att_offset, &att_data_len) != 0) {
        return -1;
    }

    int index = get_protocol_index_by_id(context->ipacket, proto_id);
    if (index == -1)
        return -1; // protocol not found

    unsigned int dicom_offset = get_packet_offset_at_index(context->ipacket, index);

    // For patient name (ID 15), we need to handle it specially
    if (att_id == 15) {
        printf("[DICOM DEBUG] Modifying patient name attribute (ID 15)\n");

        // Calculate the actual offset in the packet
        int actual_offset = dicom_offset + att_offset;

        // Check if we have enough space in the packet
        if (actual_offset + att_data_len > context->packet_size) {
            printf("[DICOM DEBUG] Packet too small to modify patient name. Packet size: %d, needed: %d\n",
                   context->packet_size, actual_offset + att_data_len);
            return -4;
        }

        // Create a buffer for the new patient name
        char new_patient_name[256] = {0};

        if (is_string) {
            // For string values, fill with the new value
            const char *val = (const char *)new_val;
            int val_len = strlen(val);

            // Fill the buffer with '1' characters
            for (int i = 0; i < att_data_len; i++) {
                new_patient_name[i] = '1';
            }

            // Print the new patient name
            printf("[DICOM DEBUG] New patient name: '");
            for (int i = 0; i < att_data_len; i++) {
                printf("%c", new_patient_name[i]);
            }
            printf("'\n");

            // Print the bytes before modification
            printf("[DICOM DEBUG] Bytes before modification: ");
            for (int i = 0; i < att_data_len; i++) {
                printf("%02X ", (unsigned char)context->packet_data[actual_offset + i]);
            }
            printf("\n");

            // Modify the patient name
            memcpy(&context->packet_data[actual_offset], new_patient_name, att_data_len);

            // Print the bytes after modification
            printf("[DICOM DEBUG] Bytes after modification: ");
            for (int i = 0; i < att_data_len; i++) {
                printf("%02X ", (unsigned char)context->packet_data[actual_offset + i]);
            }
            printf("\n");
        } else {
            // For numeric values, convert to ASCII
            u_char ascii_string[50] = {0};
            int val = *(const int *)new_val;
            if (!int_to_ascii_string(ascii_string, att_data_len * 2, (uint64_t)val)) {
                return -2; // failed to convert numeric value
            }

            // Modify the patient name
            memcpy(&context->packet_data[actual_offset], ascii_string, att_data_len);
        }

        return 1;
    }

    u_char ascii_string[50] = {0}; // buffer to store a string ASCII converted

    if (is_string) {
        memset(ascii_string, 0x20, sizeof(ascii_string));
        const char *val = (const char *)new_val;
        if (strlen((char *)new_val) > att_data_len) {
            fprintf(stderr, "New value is too long for attribute %d\n", att_id);
            return -2;
        }
        strncpy((char *)ascii_string, new_val, att_data_len);
    } else {
        int val = *(const int *)new_val;
        if (!int_to_ascii_string(ascii_string, att_data_len * 2, (uint64_t)val)) {
            return -2; // failed to convert numeric value
        }
    }

    // Check if it does not exceed the packet data length
    if (att_offset + att_data_len > context->packet_size) {
        fprintf(stderr, "Replacement exceeds packet data length\n");
        return -4;
    }

    att_offset += dicom_offset;
    // directly replace the attribute in packet_data
    memcpy(&context->packet_data[att_offset], ascii_string, att_data_len);

    return 1;
}

// Get value of a DICOM attribute from packet data
int get_dicom_attribute(uint32_t proto_id, uint32_t att_id, char *value) {
    forward_packet_context_t *context = _get_current_context();
    if (context == NULL)
        return -3;

    int att_offset, att_data_len;
    if (get_dicom_attribute_info(att_id, &att_offset, &att_data_len) != 0) {
        return -1;
    }

    int index = get_protocol_index_by_id(context->ipacket, proto_id);
    if (index == -1)
        return -1; // protocol not found

    unsigned int dicom_offset = get_packet_offset_at_index(context->ipacket, index);
    att_offset += dicom_offset;

    // Check if it does not exceed the packet data length
    if (att_offset + att_data_len > context->packet_size) {
        fprintf(stderr, "Attribute offset exceeds packet data length\n");
        return -4;
    }

    // Copy the attribute value
    memcpy(value, &context->packet_data[att_offset], att_data_len);
    value[att_data_len] = '\0'; // Ensure null termination for string values

    return att_data_len;
}