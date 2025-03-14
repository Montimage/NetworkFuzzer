/*
 * inject_dicom.h
 */

#ifndef SRC_MODULES_SECURITY_FORWARD_PROTO_INJECT_DICOM_H_
#define SRC_MODULES_SECURITY_FORWARD_PROTO_INJECT_DICOM_H_

#include "../../engine/configure.h"

typedef struct inject_dicom_context_struct inject_dicom_context_t;

inject_dicom_context_t* inject_dicom_alloc(const forward_packet_target_conf_t *conf, uint32_t nb_copies);
int inject_dicom_send_packet(inject_dicom_context_t *context, const uint8_t *packet_data, uint16_t packet_size);
void inject_dicom_release(inject_dicom_context_t *context);

#endif /* SRC_MODULES_SECURITY_FORWARD_PROTO_INJECT_DICOM_H_ */
