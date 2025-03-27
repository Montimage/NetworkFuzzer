# DICOM Protocol Basics

## Introduction to DICOM

DICOM (Digital Imaging and Communications in Medicine) is the international standard for medical images and related information. It defines the formats for medical images that can be exchanged with the data and quality necessary for clinical use.

DICOM was developed by the American College of Radiology (ACR) and the National Electrical Manufacturers Association (NEMA). The standard is maintained by the DICOM Standards Committee.

## Key DICOM Concepts

### DICOM Information Objects

DICOM Information Objects include:
- Images (CT, MRI, X-Ray, Ultrasound, etc.)
- Waveforms (ECG)
- Structured Reports
- Treatment plans
- Encapsulated documents (e.g. PDFs)

### DICOM Network Services

DICOM network services include:
- Storage (sending images)
- Query/Retrieve (finding and getting images)
- Worklist Management (getting patient/study details)
- Print Management (sending images to DICOM printers)
- Modality Performed Procedure Step (tracking imaging procedure status)

## DICOM Networking

### DICOM Application Entities (AEs)

Each DICOM device or application is represented as an Application Entity (AE). Each AE has:
- An AE Title (AET): A unique name (up to 16 characters)
- A TCP/IP address and port number

### DICOM Association Negotiation

DICOM uses a connection-oriented approach with these stages:
1. A-ASSOCIATE-RQ: The initiating AE requests an association
2. A-ASSOCIATE-AC: The accepting AE accepts the association
3. A-ASSOCIATE-RJ: The accepting AE rejects the association
4. Data transfer (if accepted)
5. A-RELEASE-RQ: Request to end the association
6. A-RELEASE-RP: Response to release request
7. A-ABORT: Abnormal termination of the association

### DICOM PDU (Protocol Data Unit) Structure

All DICOM messages over the network are encapsulated in PDUs. PDU types include:
- 0x01: A-ASSOCIATE-RQ
- 0x02: A-ASSOCIATE-AC
- 0x03: A-ASSOCIATE-RJ
- 0x04: P-DATA-TF (data transfer)
- 0x05: A-RELEASE-RQ
- 0x06: A-RELEASE-RP
- 0x07: A-ABORT

## A-ASSOCIATE-RQ PDU Structure

The A-ASSOCIATE-RQ PDU is structured as follows:

1. PDU Type (1 byte): 0x01
2. Reserved (1 byte): 0x00
3. PDU Length (4 bytes): Length of PDU in bytes
4. Protocol Version (2 bytes): 0x0001
5. Reserved (2 bytes): 0x0000
6. Called AE Title (16 bytes): AE Title of the receiver
7. Calling AE Title (16 bytes): AE Title of the sender
8. Reserved (32 bytes): All zeros
9. Application Context Item:
   - Item Type (1 byte): 0x10
   - Reserved (1 byte): 0x00
   - Item Length (2 bytes)
   - Application Context Name (Variable): Usually 1.2.840.10008.3.1.1.1
10. Presentation Context Items (One or more):
    - Item Type (1 byte): 0x20
    - Reserved (1 byte): 0x00
    - Item Length (2 bytes)
    - Presentation Context ID (1 byte)
    - Reserved (3 bytes): 0x000000
    - Abstract Syntax Item:
      - Item Type (1 byte): 0x30
      - Reserved (1 byte): 0x00
      - Item Length (2 bytes)
      - Abstract Syntax Name (Variable): SOP Class UID
    - Transfer Syntax Items (One or more):
      - Item Type (1 byte): 0x40
      - Reserved (1 byte): 0x00
      - Item Length (2 bytes)
      - Transfer Syntax Name (Variable): Transfer Syntax UID
11. User Information Item:
    - Item Type (1 byte): 0x50
    - Reserved (1 byte): 0x00
    - Item Length (2 bytes)
    - User Information Sub-Items (One or more):
      - Maximum PDU Length Sub-Item
      - Implementation Class UID Sub-Item
      - Implementation Version Name Sub-Item (Optional)
      - Other Sub-Items (Optional)

## Common Error Scenarios

### Association Rejected

Common reasons for A-ASSOCIATE-RJ:
1. Called AE Title not recognized (Invalid AE Title)
2. Calling AE Title not recognized (Not authorized)
3. No presentation context accepted (Unsupported SOP classes or transfer syntaxes)
4. Server temporary congestion
5. Server limit reached for associations

### DICOM Response Status Codes

Common status codes:
- 0x0000: Success
- 0x0001: Success with warnings
- 0xA7xx: Refused: Out of resources
- 0xA9xx: Error: Data Set does not match SOP Class
- 0xCxxx: Refused: Unable to process
- 0xFE00: Cancel

## DICOM Security

DICOM provides several security mechanisms:
1. TLS for secure transport
2. Digital signatures for data integrity
3. Attribute level confidentiality for data de-identification
4. User authentication

## Debugging DICOM Connections

When debugging DICOM connections, check:
1. Network connectivity (ping, telnet)
2. AE Title configuration
3. IP address and port configuration
4. Firewall settings
5. Supported SOP classes and transfer syntaxes
6. PDU size limitations

Tools like Wireshark with DICOM dissectors can help analyze DICOM traffic.