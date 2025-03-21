# DICOM Network Traffic Dataset

This dataset contains **DICOM (Digital Imaging and Communications in Medicine)** network traffic in pcap format, designed for analyzing, testing, and improving the robustness of DICOM servers and network security tools. The dataset includes the following:

## **1. Normal Traffic**
This folder contains traffic that reflects typical DICOM operations, including association negotiation (A-ASSOCIATE), connectivity verification (C-ECHO), query/retrieve workflows (C-FIND and C-MOVE), and data storage operations (C-STORE). The traffic is captured by simulating valid communication between a DICOM client and an Orthanc server.

## **2. Abnormal Traffic**
This folder contains traffic with anomalies introduced by modifying specific attributes of legitimate packets using our tool NetworkFuzzer. These include invalid or unexpected PDU types, oversized or malformed AE titles, unsupported or inconsistent command fields, etc.

This dataset is suitable for protocol analysis, machine learning research, and IDS/IPS evaluation.