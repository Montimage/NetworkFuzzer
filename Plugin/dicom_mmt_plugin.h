/* Generated with MMT Plugin Generator */

#ifndef DICOM_H
#define DICOM_H
#ifdef	__cplusplus
extern "C" {
#endif

#include "plugin_defs.h"
#include "mmt_core.h"


#define PROTO_DICOM 701

#define PROTO_DICOM_ALIAS "dicom"

#define PROTO_DICOM_HDRLEN 6
#define DICOM_PAYLOAD_MIN_LEN 4

// DICOM PDU Types
	enum dicom_pdu_type {
		A_ASSOCIATE_RQ = 1,
		A_ASSOCIATE_AC = 2,
		A_ASSOCIATE_RJ = 3,
		P_DATA_TF = 4,
		A_RELEASE_RQ = 5,
		A_RELEASE_RP = 6,
		A_ABORT = 7
	};

	enum dicom_attributes {

		DICOM_PDU_TYPE = 1,
		DICOM_PDU_LEN,
		DICOM_PROTO_VERSION,
		DICOM_CALLED_AE_TITLE,
		DICOM_CALLING_AE_TITLE,
		DICOM_ATTRIBUTES_NB = DICOM_CALLING_AE_TITLE,
	};


#define DICOM_PDU_TYPE_ALIAS "pdu_type"
#define DICOM_PDU_LEN_ALIAS "pdu_len"
#define DICOM_PROTO_VERSION_ALIAS "proto_version"
#define DICOM_CALLED_AE_TITLE_ALIAS "called_ae_title"
#define DICOM_CALLING_AE_TITLE_ALIAS "calling_ae_title"

	struct dicomhdr {
		uint8_t pdu_type ;
		uint8_t reserved ;
		uint32_t pdu_len ;
	};

	int init_dicom_proto_struct();
	classified_proto_t dicom_stack_classification(ipacket_t * ipacket);
	int mmt_check_dicom_hdr(struct dicomhdr* header);
	int mmt_check_dicom_payload(struct dicomhdr* header, unsigned int packet_len);
	int mmt_check_dicom(struct dicomhdr * header, int offset, int packet_len);
	int mmt_check_dicom_tcp(ipacket_t * ipacket, unsigned index);
	static int _extraction_att(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data);

#ifndef CORE
	int init_proto();
#endif //CORE

#ifdef	__cplusplus
}
#endif
#endif	/* DICOM_H */


