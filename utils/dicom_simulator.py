import os
import argparse
from pydicom import dcmread
from pydicom.uid import JPEGBaseline, ImplicitVRLittleEndian, ExplicitVRLittleEndian
from pynetdicom import AE, StoragePresentationContexts, QueryRetrievePresentationContexts
from pynetdicom.sop_class import (
    CTImageStorage,
    MRImageStorage,
    XRayAngiographicImageStorage,
    SecondaryCaptureImageStorage,
    ComputedRadiographyImageStorage,
    Verification,
    PatientRootQueryRetrieveInformationModelFind,
    PatientRootQueryRetrieveInformationModelGet
)
from pydicom.dataset import Dataset

def add_storage_presentation_contexts(ae):
    """Add presentation contexts for common DICOM storage SOP classes."""
    storage_sop_classes = [
        CTImageStorage,
        MRImageStorage,
        XRayAngiographicImageStorage,
        SecondaryCaptureImageStorage,
        ComputedRadiographyImageStorage
    ]

    transfer_syntaxes = [
        ImplicitVRLittleEndian,
        ExplicitVRLittleEndian,
        JPEGBaseline
    ]

    for sop_class in storage_sop_classes:
        ae.add_requested_context(sop_class, transfer_syntaxes)

def send_c_echo(ae, pacs_ip, pacs_port, pacs_ae_title):
    """Send a C-ECHO request to verify connectivity."""
    assoc = ae.associate(pacs_ip, pacs_port, ae_title=pacs_ae_title)
    if assoc.is_established:
        print("Connected. Sending C-ECHO...")
        status = assoc.send_c_echo()
        print(f"C-ECHO response: {status.Status}")
        assoc.release()
    else:
        print("Failed to connect.")

def send_c_store(ae, dicom_folder, pacs_ip, pacs_port, pacs_ae_title):
    """Send DICOM images to PACS using C-STORE."""
    # Ensure the output folder exists
    if not os.path.exists(dicom_folder):
        print(f"Error: Folder {dicom_folder} does not exist")
        return

    print(f"\n[*] Looking for DICOM files in: {dicom_folder}")

    # Get list of DICOM files first
    dicom_files = [f for f in os.listdir(dicom_folder) if f.lower().endswith('.dcm')]
    if not dicom_files:
        print("[-] No DICOM files found in the specified folder")
        return

    print(f"[*] Found {len(dicom_files)} DICOM files")

    # First pass: read all files and collect their SOP Class UIDs and transfer syntaxes
    sop_classes = set()
    transfer_syntaxes = set()
    for filename in dicom_files:
        try:
            filepath = os.path.join(dicom_folder, filename)
            dataset = dcmread(filepath)
            if hasattr(dataset, 'SOPClassUID'):
                sop_classes.add(dataset.SOPClassUID)
            if hasattr(dataset.file_meta, 'TransferSyntaxUID'):
                transfer_syntaxes.add(dataset.file_meta.TransferSyntaxUID)
            else:
                transfer_syntaxes.add(ImplicitVRLittleEndian)  # Default to ImplicitVRLittleEndian if none found
        except Exception as e:
            print(f"[-] Error reading {filename}: {str(e)}")
            continue

    # Add presentation contexts for all SOP Classes with all transfer syntaxes
    print("\n[*] Adding presentation contexts for all SOP Classes")
    for sop_class in sop_classes:
        print(f"[*] Adding context for: {sop_class}")
        for ts in transfer_syntaxes:
            ae.add_requested_context(sop_class, [ts])

    # Create association with all necessary presentation contexts
    print(f"\n[*] Attempting to connect to {pacs_ae_title} at {pacs_ip}:{pacs_port}")
    assoc = ae.associate(pacs_ip, pacs_port, ae_title=pacs_ae_title)
    if assoc.is_established:
        print("[+] Connected. Sending C-STORE...")

        # Second pass: send the files
        for filename in dicom_files:
            try:
                print(f"\n[*] Processing: {filename}")
                filepath = os.path.join(dicom_folder, filename)
                print(f"[*] Reading file: {filepath}")
                dataset = dcmread(filepath)

                # Print some information about the DICOM file
                print(f"    Modality: {getattr(dataset, 'Modality', 'N/A')}")
                print(f"    SOP Class UID: {getattr(dataset, 'SOPClassUID', 'N/A')}")
                print(f"    Transfer Syntax: {getattr(dataset.file_meta, 'TransferSyntaxUID', 'N/A')}")

                # Send the dataset
                print("[*] Sending dataset...")
                status = assoc.send_c_store(dataset)
                if status:
                    print(f"[+] Sent {filename}: Status {hex(status.Status)}")
                    if status.Status != 0x0000:
                        print(f"[-] Warning: Unexpected status {hex(status.Status)}")
                else:
                    print(f"[-] Failed to send {filename}")

            except Exception as e:
                print(f"[-] Error processing {filename}: {str(e)}")
                continue

        print("\n[*] Releasing association")
        assoc.release()
    else:
        print("[-] Failed to connect.")

def send_c_find(ae, pacs_ip, pacs_port, pacs_ae_title, query_level="PATIENT"):
    """Send a C-FIND request with dynamic query level."""
    print(f"\n[*] Preparing C-FIND query at {query_level} level")

    # Set the query level and build the query dataset
    query = Dataset()
    query.QueryRetrieveLevel = query_level
    query.SpecificCharacterSet = "ISO_IR 100"

    # Add required search attributes based on query level
    if query_level == "PATIENT":
        query.PatientName = ""
        query.PatientID = ""
        print("[*] Searching for all patients")
    elif query_level == "STUDY":
        # For study level, explicitly request all relevant fields
        query.StudyInstanceUID = ""
        query.StudyDate = ""
        query.StudyTime = ""
        query.AccessionNumber = ""
        query.StudyID = ""
        query.StudyDescription = ""
        query.PatientName = ""
        query.PatientID = ""
        query.NumberOfStudyRelatedSeries = ""
        query.NumberOfStudyRelatedInstances = ""
        print("[*] Searching for all studies")
    elif query_level == "SERIES":
        query.StudyInstanceUID = ""
        query.SeriesInstanceUID = ""
        query.Modality = ""
        query.SeriesNumber = ""
        query.SeriesDescription = ""
        print("[*] Searching for all series")
    elif query_level == "IMAGE":
        query.StudyInstanceUID = ""
        query.SeriesInstanceUID = ""
        query.SOPInstanceUID = ""
        query.InstanceNumber = ""
        print("[*] Searching for all images")
    else:
        print("[-] Unsupported query level.")
        return

    # Create an association to the PACS server
    print(f"[*] Attempting to connect to {pacs_ae_title} at {pacs_ip}:{pacs_port}")
    assoc = ae.associate(pacs_ip, pacs_port, ae_title=pacs_ae_title)

    if assoc.is_established:
        print(f"[+] Connected. Sending C-FIND for {query_level.lower()}...")
        print("-" * 80)

        # Send the C-FIND request to the PACS server
        responses = assoc.send_c_find(query, PatientRootQueryRetrieveInformationModelFind)
        response_count = 0

        for status, identifier in responses:
            if status:
                if status.Status == 0xFF00:  # Pending
                    response_count += 1
                    if identifier:
                        print(f"\n{query_level} Result #{response_count}:")
                        print("=" * 40)

                        # Get max length for formatting
                        max_key_length = max(len(elem.name) for elem in identifier if elem.value != "")

                        # Print each attribute in a formatted way
                        for elem in identifier:
                            if elem.value != "":
                                # Skip Query/Retrieve Level in the output as it's redundant
                                if elem.name != "Query/Retrieve Level":
                                    value = str(elem.value) if elem.value is not None else "None"
                                    print(f"{elem.name:<{max_key_length}}: {value}")

                        # For STUDY level, highlight the StudyInstanceUID as it's needed for C-GET
                        if query_level == "STUDY" and hasattr(identifier, 'StudyInstanceUID'):
                            print("\n[*] StudyInstanceUID for C-GET: " + identifier.StudyInstanceUID)

                elif status.Status == 0x0000:  # Success
                    print("\n[+] C-FIND completed successfully")
                    if response_count == 0:
                        print("    No matching results found")
                    else:
                        print(f"    Total results found: {response_count}")
                else:
                    print(f"\n[-] C-FIND failed with status: {hex(status.Status)}")
                    if status.Status == 0xC000:
                        print("    Error: Unable to process query (possibly invalid query parameters)")
            else:
                print("\n[-] C-FIND response received without status")

        print("-" * 80)
        print("[*] Releasing association")
        assoc.release()
    else:
        print("[-] Failed to connect to the PACS server.")

def send_c_get(ae, pacs_ip, pacs_port, pacs_ae_title, study_uid, output_folder):
    """Retrieve images from PACS using C-GET."""
    ae.add_requested_context(PatientRootQueryRetrieveInformationModelGet)
    assoc = ae.associate(pacs_ip, pacs_port, ae_title=pacs_ae_title)

    if assoc.is_established:
        print("Connected. Sending C-GET...")
        query = Dataset()
        query.QueryRetrieveLevel = "PATIENT" #"STUDY"
        query.StudyInstanceUID = study_uid

        # Add the appropriate context for the SOP class (CTImageStorage, etc.)
        ae.add_requested_context(Verification)
        responses = assoc.send_c_get(query, PatientRootQueryRetrieveInformationModelGet)

        for status, dataset in responses:
            if status and dataset:
                filename = f"{output_folder}/{dataset.SOPInstanceUID}.dcm"
                dataset.save_as(filename)
                print(f"Retrieved and saved: {filename}")
            else:
                print("C-GET failed or was not acknowledged.")

        assoc.release()
    else:
        print("Failed to connect to the PACS server.")

def main():
    parser = argparse.ArgumentParser(description="DICOM Simulator for Various Requests")
    parser.add_argument("action", choices=['connect', 'echo', 'store', 'find', 'retrieve', 'disconnect'],
                        help="Action to perform")
    parser.add_argument("--dicom_folder", default="DICOM_images", help="Folder with DICOM files (for store)")
    parser.add_argument("--pacs_ip", required=True, help="PACS server IP address")
    parser.add_argument("--pacs_port", type=int, required=True, help="PACS server port")
    parser.add_argument("--pacs_ae_title", required=True, help="PACS AE title")
    parser.add_argument("--study_uid", help="StudyInstanceUID for retrieve")
    parser.add_argument("--output_folder", default="retrieved_images", help="Folder to save retrieved images")
    parser.add_argument("--query_level", choices=["PATIENT", "STUDY", "SERIES", "IMAGE"], default="PATIENT",
                        help="Specify the query level for C-FIND (default is 'PATIENT')")
    args = parser.parse_args()

    # Configure the Application Entity
    ae = AE(ae_title='MODALITY')

    # Add verification context
    ae.add_requested_context(Verification)

    # Add storage contexts based on the action
    if args.action == 'store':
        print("[*] Adding storage presentation contexts")
        add_storage_presentation_contexts(ae)
    elif args.action == 'find':
        ae.add_requested_context(PatientRootQueryRetrieveInformationModelFind)
    elif args.action == 'retrieve':
        ae.add_requested_context(PatientRootQueryRetrieveInformationModelGet)
        add_storage_presentation_contexts(ae)

    if args.action == 'connect':
        print("Trying to establish association...")
        assoc = ae.associate(args.pacs_ip, args.pacs_port, ae_title=args.pacs_ae_title)
        if assoc.is_established:
            print("Association established.")
            assoc.release()
        else:
            print("Failed to establish association.")
    elif args.action == 'echo':
        send_c_echo(ae, args.pacs_ip, args.pacs_port, args.pacs_ae_title)
    elif args.action == 'store':
        print("[*] Starting C-STORE operation")
        send_c_store(ae, args.dicom_folder, args.pacs_ip, args.pacs_port, args.pacs_ae_title)
    elif args.action == 'find':
        send_c_find(ae, args.pacs_ip, args.pacs_port, args.pacs_ae_title, query_level=args.query_level)
    elif args.action == 'retrieve':
        if not args.study_uid:
            print("Error: --study_uid is required for retrieval.")
            return
        send_c_get(ae, args.pacs_ip, args.pacs_port, args.pacs_ae_title, args.study_uid, args.output_folder)
    elif args.action == 'disconnect':
        print("Disconnecting (simulated).")

if __name__ == "__main__":
    main()
