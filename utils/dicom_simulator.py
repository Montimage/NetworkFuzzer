import os
import argparse
import signal
import threading
import datetime
from pydicom import dcmread
from pydicom.uid import JPEGBaseline, ImplicitVRLittleEndian, ExplicitVRLittleEndian
from pynetdicom import AE, StoragePresentationContexts, QueryRetrievePresentationContexts, evt, debug_logger
from pynetdicom.sop_class import (
    CTImageStorage,
    MRImageStorage,
    XRayAngiographicImageStorage,
    SecondaryCaptureImageStorage,
    ComputedRadiographyImageStorage,
    Verification,
    PatientRootQueryRetrieveInformationModelFind,
    PatientRootQueryRetrieveInformationModelMove,
    PatientRootQueryRetrieveInformationModelGet,
    StudyRootQueryRetrieveInformationModelFind,
    StudyRootQueryRetrieveInformationModelMove
)
from pydicom.dataset import Dataset
import logging

# Global variables
received_datasets = []
current_association = None
operation_cancelled = False
current_query_model = None

def signal_handler(signum, frame):
    """Handle Ctrl+C by initiating a C-CANCEL request."""
    global operation_cancelled
    print("\n[*] Cancellation requested. Sending C-CANCEL...")
    operation_cancelled = True

    if current_association and current_association.is_established:
        try:
            if current_query_model:
                # Different behavior based on the query model
                if current_query_model == PatientRootQueryRetrieveInformationModelFind:
                    print("[*] Sending C-CANCEL for C-FIND operation...")
                    # For C-FIND, use message ID 1 (standard)
                    current_association.send_c_cancel(msg_id=1, query_model=current_query_model)
                    print(f"[+] C-CANCEL request sent for query model: {current_query_model.name}")
                    # Don't release the association immediately - let the main function handle it
                    # This ensures that we can see the cancel status in the responses

                elif current_query_model == PatientRootQueryRetrieveInformationModelMove:
                    # For C-MOVE, send C-CANCEL and release association
                    current_association.send_c_cancel(msg_id=1, query_model=current_query_model)
                    print(f"[+] C-CANCEL request sent for query model: {current_query_model.name}")

                    # Note: For C-MOVE, this will only cancel the move request itself
                    # The actual data transfer happens over a separate association initiated by the server
                    print("[*] Note: For C-MOVE, this cancels only the move request.")
                    print("[*] Any images already in transit may still be received.")

                    print("[*] Releasing association")
                    current_association.release()

                elif current_query_model == PatientRootQueryRetrieveInformationModelGet:
                    # For C-GET, send C-CANCEL and release association
                    current_association.send_c_cancel(msg_id=1, query_model=current_query_model)
                    print(f"[+] C-CANCEL request sent for query model: {current_query_model.name}")
                    print("[*] Releasing association")
                    current_association.release()

                else:
                    # For any other operation type
                    current_association.send_c_cancel(msg_id=1, query_model=current_query_model)
                    print(f"[+] C-CANCEL request sent for query model: {current_query_model.name}")
                    print("[*] Releasing association")
                    current_association.release()
            else:
                print("[-] Unable to send C-CANCEL: No active query model")
                # Still release the association if we have one
                if current_association and current_association.is_established:
                    print("[*] Releasing association")
                    current_association.release()
        except Exception as e:
            print(f"[-] Error during C-CANCEL: {str(e)}")
            # Always try to release the association if there was an error
            if current_association and current_association.is_established:
                try:
                    current_association.release()
                    print("[*] Association released after error")
                except:
                    print("[-] Failed to release association after error")

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
    global current_association, operation_cancelled, current_query_model
    operation_cancelled = False
    current_query_model = PatientRootQueryRetrieveInformationModelFind
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
    current_association = ae.associate(pacs_ip, pacs_port, ae_title=pacs_ae_title)

    if current_association.is_established:
        print(f"[+] Connected. Sending C-FIND for {query_level.lower()}...")
        print("-" * 80)

        try:
            # Flag to track if the operation was aborted
            aborted = False

            # Send the C-FIND request to the PACS server
            responses = current_association.send_c_find(query, PatientRootQueryRetrieveInformationModelFind)
            response_count = 0

            for status, identifier in responses:
                # Check if cancellation was requested
                if operation_cancelled:
                    print("\n[*] Operation cancelled by user")
                    aborted = True
                    break

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
                                print("\n[*] StudyInstanceUID for retrieve: " + identifier.StudyInstanceUID)

                    elif status.Status == 0x0000 and not aborted:  # Success (only if not aborted)
                        print("\n[+] C-FIND completed successfully")
                        if response_count == 0:
                            print("    No matching results found")
                        else:
                            print(f"    Total results found: {response_count}")
                    elif status.Status != 0x0000 and not aborted:
                        print(f"\n[-] C-FIND failed with status: {hex(status.Status)}")
                        if status.Status == 0xC000:
                            print("    Error: Unable to process query (possibly invalid query parameters)")
                        elif status.Status == 0xFE00:
                            print("    Error: Operation cancelled")
                else:
                    if not aborted:
                        print("\n[-] C-FIND response received without status")

        except Exception as e:
            print(f"[-] Error during C-FIND operation: {str(e)}")
        finally:
            # Check if association is still established - it may have been released by the signal handler
            if current_association and current_association.is_established:
                if not operation_cancelled:  # Only release if not cancelled (signal handler does it otherwise)
                    print("-" * 80)
                    print("[*] Releasing association")
                    current_association.release()

            if operation_cancelled:
                print("[+] C-FIND operation was terminated by C-CANCEL")
    else:
        print("[-] Failed to connect to the PACS server.")

def handle_store(event):
    """Handle a C-STORE request."""
    global received_datasets, operation_cancelled

    # Add the dataset to our received list regardless of cancellation
    received_datasets.append(event.dataset)

    # Print a brief status if not cancelled
    if not operation_cancelled:
        # Get some basic info from the dataset
        modality = getattr(event.dataset, 'Modality', 'Unknown')
        instance_num = getattr(event.dataset, 'InstanceNumber', '?')

        # Print a compact notification
        print(f"\r[+] Received: {modality} #{instance_num}", end="")

    # Always return success to the sender
    return 0x0000

# TODO: C-GET failed with status: 0xa702 - the server doesn't support C-GET for this SOP Class
def send_c_get(ae, pacs_ip, pacs_port, pacs_ae_title, study_uid, output_folder):
    """Retrieve images from PACS using C-GET."""
    global received_datasets, current_association, operation_cancelled, current_query_model
    received_datasets = []
    operation_cancelled = False
    current_query_model = PatientRootQueryRetrieveInformationModelGet

    print(f"\n[*] Preparing C-GET request for StudyInstanceUID: {study_uid}")

    # Ensure output directory exists
    os.makedirs(output_folder, exist_ok=True)

    # Configure Storage SCP
    print("[*] Configuring Storage SCP")
    handlers = [(evt.EVT_C_STORE, handle_store)]
    scp = AE(ae_title='MODALITY')

    # Add storage contexts with all transfer syntaxes
    storage_sop_classes = [
        CTImageStorage, MRImageStorage, XRayAngiographicImageStorage,
        SecondaryCaptureImageStorage, ComputedRadiographyImageStorage
    ]
    transfer_syntaxes = [ImplicitVRLittleEndian, ExplicitVRLittleEndian, JPEGBaseline]

    print("[*] Adding storage contexts with transfer syntaxes:")
    for sop_class in storage_sop_classes:
        scp.add_supported_context(sop_class, transfer_syntaxes)
        print(f"    - {sop_class.name}")

    # Start Storage SCP
    try:
        print("[*] Starting Storage SCP on port 4242")
        scp.start_server(('', 4242), block=False, evt_handlers=handlers)
        print("[+] Storage SCP started successfully")
    except Exception as e:
        print(f"[-] Error starting Storage SCP: {str(e)}")
        return

    # Add C-GET context with all transfer syntaxes
    print("[*] Adding C-GET presentation context")
    ae.add_requested_context(PatientRootQueryRetrieveInformationModelGet, transfer_syntaxes)
    add_storage_presentation_contexts(ae)

    # Create association and send C-GET request
    print(f"[*] Attempting to establish association with {pacs_ae_title}")
    current_association = ae.associate(pacs_ip, pacs_port, ae_title=pacs_ae_title)
    if not current_association.is_established:
        print("[-] Failed to establish association")
        scp.shutdown()
        return

    print("[+] Association established")
    print("[*] Checking accepted presentation contexts:")
    for cx in current_association.accepted_contexts:
        print(f"    - {cx.abstract_syntax.name}")

    # Prepare and send C-GET request
    query = Dataset()
    query.QueryRetrieveLevel = "STUDY"
    query.StudyInstanceUID = study_uid

    try:
        print("[*] Sending C-GET request...")
        responses = current_association.send_c_get(query, PatientRootQueryRetrieveInformationModelGet)

        for status, identifier in responses:
            if operation_cancelled:
                print("\n[*] Operation cancelled by user")
                break

            if not status:
                print("[-] Received empty status")
                continue

            if status.Status == 0xFF00:  # Pending
                print("[*] C-GET operation in progress...")
            elif status.Status == 0x0000:  # Success
                # Save received datasets
                for i, dataset in enumerate(received_datasets, 1):
                    series_num = getattr(dataset, 'SeriesNumber', '000')
                    instance_num = getattr(dataset, 'InstanceNumber', '000')
                    sop_uid = getattr(dataset, 'SOPInstanceUID', f'unknown_{i}')

                    filename = f"{output_folder}/Series{series_num}_Instance{instance_num}_{sop_uid}.dcm"
                    dataset.save_as(filename)
                    print(f"[+] Saved image {i}:")
                    print(f"    Series Number: {series_num}")
                    print(f"    Instance Number: {instance_num}")
                    print(f"    Saved as: {filename}")

                print(f"\n[+] Total images retrieved: {len(received_datasets)}")
            else:
                print(f"[-] C-GET failed with status: {hex(status.Status)}")
                if status.Status == 0xA701:
                    print("    Error: Refused - Out of Resources")
                elif status.Status == 0xA702:
                    print("    Error: Failed - Unable to perform sub-operations")
                    print("    Note: This might indicate the server doesn't support C-GET for this SOP Class")
                elif status.Status == 0xA900:
                    print("    Error: Failed - Identifier does not match SOP Class")
                elif status.Status == 0xC000:
                    print("    Error: Failed - Unable to process")
                if hasattr(status, 'ErrorComment'):
                    print(f"    Server message: {status.ErrorComment}")

    except Exception as e:
        print(f"[-] Error during C-GET operation: {str(e)}")
    finally:
        if not operation_cancelled:  # Only release if not cancelled
            print("[*] Releasing association")
            current_association.release()
        print("[*] Stopping Storage SCP")
        scp.shutdown()

def send_c_move(ae, pacs_ip, pacs_port, pacs_ae_title, study_uid, output_folder):
    """Retrieve images from PACS using C-MOVE."""
    global received_datasets, current_association, operation_cancelled, current_query_model
    received_datasets = []
    operation_cancelled = False
    current_query_model = PatientRootQueryRetrieveInformationModelMove

    print("\n[*] Preparing C-MOVE request for StudyInstanceUID: " + study_uid)
    print("[*] Note: C-MOVE operations work by instructing the PACS server to")
    print("[*] send images to our DICOM Storage SCP. If you cancel, only the")
    print("[*] initial request is cancelled, but images may continue to arrive.")

    # Ensure output directory exists
    os.makedirs(output_folder, exist_ok=True)

    # Configure Storage SCP
    handlers = [(evt.EVT_C_STORE, handle_store)]
    scp = AE(ae_title='MODALITY')

    # Add storage contexts with all transfer syntaxes
    storage_sop_classes = [
        CTImageStorage, MRImageStorage, XRayAngiographicImageStorage,
        SecondaryCaptureImageStorage, ComputedRadiographyImageStorage
    ]
    for sop_class in storage_sop_classes:
        scp.add_supported_context(sop_class)

    # Start Storage SCP
    try:
        print("[*] Starting Storage SCP on port 4242")
        scp.start_server(('', 4242), block=False, evt_handlers=handlers)
        print("[+] Storage SCP started successfully")
    except Exception as e:
        print(f"[-] Error starting Storage SCP: {str(e)}")
        return

    # Add C-MOVE context and storage contexts
    ae.add_requested_context(PatientRootQueryRetrieveInformationModelMove)
    add_storage_presentation_contexts(ae)

    # Create association and send C-MOVE request
    print(f"[*] Connecting to {pacs_ae_title} at {pacs_ip}:{pacs_port}")
    current_association = ae.associate(pacs_ip, pacs_port, ae_title=pacs_ae_title)
    if not current_association.is_established:
        print("[-] Failed to connect to PACS server")
        scp.shutdown()
        return

    print("[+] Association established. Sending C-MOVE request...")

    # Prepare and send C-MOVE request
    query = Dataset()
    query.QueryRetrieveLevel = "STUDY"
    query.StudyInstanceUID = study_uid

    try:
        responses = current_association.send_c_move(query, 'MODALITY', PatientRootQueryRetrieveInformationModelMove)
        move_in_progress = False
        files_received = 0

        for status, identifier in responses:
            if operation_cancelled and not move_in_progress:
                print("\n[*] Operation cancelled by user")
                break

            if not status:
                continue

            if status.Status == 0xFF00:  # Pending
                move_in_progress = True
                print("[*] C-MOVE operation in progress...")
                # Print a dot to show progress without cluttering the console
                print(".", end="", flush=True)
            elif status.Status == 0x0000:  # Success
                print("\n[+] C-MOVE request completed successfully")

                # Continue to receive and save datasets even if the operation was cancelled
                # Process all datasets that were received
                for i, dataset in enumerate(received_datasets, 1):
                    if operation_cancelled and i > files_received:
                        # Only save files that arrived before cancellation
                        print(f"[*] Skipping {len(received_datasets) - files_received} files received after cancellation")
                        break

                    series_num = getattr(dataset, 'SeriesNumber', '000')
                    instance_num = getattr(dataset, 'InstanceNumber', '000')
                    sop_uid = getattr(dataset, 'SOPInstanceUID', f'unknown_{i}')

                    filename = f"{output_folder}/Series{series_num}_Instance{instance_num}_{sop_uid}.dcm"
                    dataset.save_as(filename)
                    files_received += 1
                    print(f"[+] Saved image {i}:")
                    print(f"    Series Number: {series_num}")
                    print(f"    Instance Number: {instance_num}")
                    print(f"    Saved as: {filename}")

                print(f"\n[+] Total images retrieved: {files_received}")
                if files_received < len(received_datasets):
                    print(f"[*] Note: {len(received_datasets) - files_received} images were received after cancellation and not saved")
            else:
                print(f"\n[-] C-MOVE failed with status: {hex(status.Status)}")
                if status.Status == 0xA701:
                    print("    Error: Refused - Out of Resources")
                elif status.Status == 0xA702:
                    print("    Error: Failed - Unable to perform sub-operations")
                elif status.Status == 0xA900:
                    print("    Error: Failed - Identifier does not match SOP Class")
                elif status.Status == 0xC000:
                    print("    Error: Failed - Unable to process")

    except Exception as e:
        print(f"\n[-] Error during C-MOVE operation: {str(e)}")
    finally:
        if not operation_cancelled:
            print("[*] Releasing association")
            if current_association.is_established:
                current_association.release()

        print("[*] Stopping Storage SCP")
        scp.shutdown()

def send_all_studies_move(ae, pacs_ip, pacs_port, pacs_ae_title, output_folder):
    """Retrieve ALL images from PACS using C-MOVE by first querying for all studies."""
    global received_datasets, current_association, operation_cancelled, current_query_model

    print("\n[*] Preparing to move ALL studies from PACS")
    print("[*] This will first query for all studies, then retrieve each one")

    # Step 1: Find all studies in the PACS
    print("\n[*] STEP 1: Finding all studies in the PACS")
    study_uids = []

    # Explicitly add the presentation context for C-FIND
    ae.add_requested_context(PatientRootQueryRetrieveInformationModelFind)

    # Build study-level query
    query = Dataset()
    query.QueryRetrieveLevel = "STUDY"
    query.StudyInstanceUID = ""
    query.PatientName = ""
    query.PatientID = ""
    query.StudyDate = ""
    query.StudyDescription = ""
    query.SpecificCharacterSet = "ISO_IR 100"

    # Variables to track which model worked for C-FIND
    using_study_root = False
    find_successful = False

    # Create an association for the C-FIND
    print(f"[*] Attempting to connect to {pacs_ae_title} at {pacs_ip}:{pacs_port}")
    find_assoc = ae.associate(pacs_ip, pacs_port, ae_title=pacs_ae_title)

    if not find_assoc.is_established:
        print("[-] Failed to connect to PACS server for study query")
        return

    # Check if the necessary presentation context was accepted
    find_context_accepted = False
    for context in find_assoc.accepted_contexts:
        if context.abstract_syntax == PatientRootQueryRetrieveInformationModelFind:
            find_context_accepted = True
            break

    if not find_context_accepted:
        print("[-] The PACS server did not accept the presentation context for Patient Root Query C-FIND")
        print("[*] Trying with Study Root Query/Retrieve Information Model instead...")
        find_assoc.release()

        # Try with Study Root instead
        ae.add_requested_context(StudyRootQueryRetrieveInformationModelFind)

        find_assoc = ae.associate(pacs_ip, pacs_port, ae_title=pacs_ae_title)
        if not find_assoc.is_established:
            print("[-] Failed to connect to PACS server for study query")
            return

        try:
            # Perform the C-FIND to get all studies with Study Root model
            print("[*] Querying for all studies using Study Root Information Model...")
            responses = find_assoc.send_c_find(query, StudyRootQueryRetrieveInformationModelFind)
            for status, identifier in responses:
                if status and status.Status == 0xFF00:  # Pending
                    if identifier and hasattr(identifier, 'StudyInstanceUID'):
                        study_uids.append(identifier.StudyInstanceUID)
                        patient_name = getattr(identifier, 'PatientName', 'Unknown')
                        study_date = getattr(identifier, 'StudyDate', 'Unknown')
                        study_desc = getattr(identifier, 'StudyDescription', 'Unknown')
                        print(f"[+] Found Study: {identifier.StudyInstanceUID}")
                        print(f"    Patient: {patient_name}")
                        print(f"    Date: {study_date}")
                        print(f"    Description: {study_desc}")
                        print("-" * 40)
            using_study_root = True
            find_successful = True
        except Exception as e:
            print(f"[-] Error during study query with Study Root model: {str(e)}")
        finally:
            print("[*] Releasing find association")
            find_assoc.release()
    else:
        try:
            # Perform the C-FIND to get all studies with Patient Root model
            print("[*] Querying for all studies using Patient Root Information Model...")
            responses = find_assoc.send_c_find(query, PatientRootQueryRetrieveInformationModelFind)
            for status, identifier in responses:
                if status and status.Status == 0xFF00:  # Pending
                    if identifier and hasattr(identifier, 'StudyInstanceUID'):
                        study_uids.append(identifier.StudyInstanceUID)
                        patient_name = getattr(identifier, 'PatientName', 'Unknown')
                        study_date = getattr(identifier, 'StudyDate', 'Unknown')
                        study_desc = getattr(identifier, 'StudyDescription', 'Unknown')
                        print(f"[+] Found Study: {identifier.StudyInstanceUID}")
                        print(f"    Patient: {patient_name}")
                        print(f"    Date: {study_date}")
                        print(f"    Description: {study_desc}")
                        print("-" * 40)
            using_study_root = False
            find_successful = True
        except Exception as e:
            print(f"[-] Error during study query: {str(e)}")
        finally:
            print("[*] Releasing find association")
            find_assoc.release()

    if not study_uids:
        print("[-] No studies found in PACS")
        return

    # Ask for confirmation before proceeding
    print(f"[*] Found {len(study_uids)} studies. Proceeding to move all images.")
    print("[*] This operation may take a long time depending on the number of studies.")

    # Step 2: Move each study one by one
    print("\n[*] STEP 2: Moving all studies")

    # Ensure output directory exists
    os.makedirs(output_folder, exist_ok=True)

    # Configure Storage SCP for receiving images
    handlers = [(evt.EVT_C_STORE, handle_store)]
    scp = AE(ae_title='MODALITY')

    # Add storage contexts
    storage_sop_classes = [
        CTImageStorage, MRImageStorage, XRayAngiographicImageStorage,
        SecondaryCaptureImageStorage, ComputedRadiographyImageStorage
    ]
    for sop_class in storage_sop_classes:
        scp.add_supported_context(sop_class)

    # Start Storage SCP
    try:
        print("[*] Starting Storage SCP on port 4242")
        scp.start_server(('', 4242), block=False, evt_handlers=handlers)
        print("[+] Storage SCP started successfully")
    except Exception as e:
        print(f"[-] Error starting Storage SCP: {str(e)}")
        return

    # Add C-MOVE context based on which model worked for C-FIND
    if using_study_root:
        print("[*] Using Study Root Query/Retrieve Information Model for C-MOVE")
        ae.add_requested_context(StudyRootQueryRetrieveInformationModelMove)
        move_model = StudyRootQueryRetrieveInformationModelMove
    else:
        print("[*] Using Patient Root Query/Retrieve Information Model for C-MOVE")
        ae.add_requested_context(PatientRootQueryRetrieveInformationModelMove)
        move_model = PatientRootQueryRetrieveInformationModelMove

    add_storage_presentation_contexts(ae)

    # Track total stats
    total_images_moved = 0
    total_studies_moved = 0
    failed_studies = []

    # Process each study
    for i, study_uid in enumerate(study_uids, 1):
        print(f"\n[*] Processing study {i}/{len(study_uids)}: {study_uid}")

        # Reset for this study
        received_datasets = []
        operation_cancelled = False
        current_query_model = move_model

        # Create a study-specific folder
        study_folder = f"{output_folder}/Study_{study_uid.replace('.', '_')}"
        os.makedirs(study_folder, exist_ok=True)

        # Create association for C-MOVE
        current_association = ae.associate(pacs_ip, pacs_port, ae_title=pacs_ae_title)
        if not current_association.is_established:
            print(f"[-] Failed to connect to PACS server for study {study_uid}")
            failed_studies.append(study_uid)
            continue

        # Check if the necessary presentation context was accepted for C-MOVE
        move_context_accepted = False
        for context in current_association.accepted_contexts:
            if context.abstract_syntax == move_model:
                move_context_accepted = True
                break

        if not move_context_accepted:
            print(f"[-] The PACS server did not accept the presentation context for C-MOVE for study {study_uid}")
            current_association.release()
            failed_studies.append(study_uid)
            continue

        # Prepare and send C-MOVE request
        query = Dataset()
        query.QueryRetrieveLevel = "STUDY"
        query.StudyInstanceUID = study_uid

        try:
            # Perform the actual C-MOVE
            responses = current_association.send_c_move(query, 'MODALITY', move_model)
            move_in_progress = False
            files_received = 0

            for status, identifier in responses:
                if operation_cancelled:
                    print("\n[*] Operation cancelled by user")
                    failed_studies.append(study_uid)
                    break

                if not status:
                    continue

                if status.Status == 0xFF00:  # Pending
                    move_in_progress = True
                    print("[*] Move in progress...", end="", flush=True)
                elif status.Status == 0x0000:  # Success
                    print("\n[+] Study move completed successfully")

                    # Save the received datasets
                    for j, dataset in enumerate(received_datasets, 1):
                        series_num = getattr(dataset, 'SeriesNumber', '000')
                        instance_num = getattr(dataset, 'InstanceNumber', '000')
                        sop_uid = getattr(dataset, 'SOPInstanceUID', f'unknown_{j}')

                        filename = f"{study_folder}/Series{series_num}_Instance{instance_num}_{sop_uid}.dcm"
                        dataset.save_as(filename)
                        files_received += 1

                    print(f"[+] Saved {files_received} images for study {study_uid}")
                    total_images_moved += files_received
                    total_studies_moved += 1
                else:
                    print(f"\n[-] C-MOVE failed with status: {hex(status.Status)}")
                    failed_studies.append(study_uid)

        except Exception as e:
            print(f"[-] Error during C-MOVE for study {study_uid}: {str(e)}")
            failed_studies.append(study_uid)
        finally:
            if current_association.is_established:
                current_association.release()
                print(f"[*] Released association for study {study_uid}")

        # Check if user wants to cancel the entire operation
        if operation_cancelled:
            print("[*] Entire operation cancelled by user")
            break

    # Final cleanup
    print("[*] Stopping Storage SCP")
    scp.shutdown()

    # Summary
    print("\n" + "=" * 50)
    print(f"[*] OPERATION SUMMARY")
    print(f"[+] Total studies processed: {total_studies_moved}/{len(study_uids)}")
    print(f"[+] Total images retrieved: {total_images_moved}")
    if failed_studies:
        print(f"[-] Failed studies: {len(failed_studies)}")
        for uid in failed_studies:
            print(f"    - {uid}")
    print("=" * 50)
    print("[*] All-studies move operation completed")

def handle_association_events(event):
    """Handle DICOM association events for detailed logging and analysis."""
    # Check event type by directly comparing the event with evt constants, not using event.event_type
    if event.event == evt.EVT_ESTABLISHED:
        assoc = event.assoc
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

        print(f"\n===== Association Established at {timestamp} =====")
        print(f"Local AE Title: {assoc.ae.ae_title}")
        print(f"Remote AE Title: {assoc.remote['ae_title']}")
        print(f"Remote Address: {assoc.remote['address']}:{assoc.remote['port']}")
        # Safely get the association ID - this can sometimes fail if active_associations isn't populated yet
        try:
            if assoc.ae.active_associations:
                print(f"Association ID: {assoc.ae.active_associations[0].association_id}")
            else:
                print(f"Association ID: Unknown (no active associations list)")
        except (IndexError, AttributeError):
            print(f"Association ID: Unknown (error accessing association data)")

        # Safely check for implementation class UID and version
        try:
            if 'implementation_class_uid' in assoc.remote:
                print(f"Implementation Class UID: {assoc.remote['implementation_class_uid']}")
            else:
                print("Implementation Class UID: Not provided")

            if 'implementation_version_name' in assoc.remote:
                print(f"Implementation Version: {assoc.remote['implementation_version_name']}")
            else:
                print("Implementation Version: Not provided")
        except Exception as e:
            print(f"Implementation information unavailable: {str(e)}")

        print("\n----- Negotiated Presentation Contexts -----")
        for context in assoc.accepted_contexts:
            print(f"\nContext ID: {context.context_id}")
            print(f"Abstract Syntax: {context.abstract_syntax} ({context.abstract_syntax.name if hasattr(context.abstract_syntax, 'name') else 'Unknown'})")
            print(f"Transfer Syntax: {context.transfer_syntax} ({context.transfer_syntax.name if hasattr(context.transfer_syntax, 'name') else 'Unknown'})")
            print(f"Result: {'Accepted' if context.result == 0 else 'Rejected'}")

        print("\n----- Extended Negotiation Information -----")
        if assoc.acceptor.extended_negotiation:
            for item in assoc.acceptor.extended_negotiation:
                print(f"SOP Class: {item.sop_class_uid}")
                print(f"App Info: {item.app_info}")
        else:
            print("No extended negotiation")

        print("\n----- User Identity Negotiation -----")
        if assoc.acceptor.user_identity:
            print(f"User Identity Type: {assoc.acceptor.user_identity.user_identity_type}")
            print(f"Response Requested: {'Yes' if assoc.acceptor.user_identity.positive_response_requested else 'No'}")
            print(f"Response Primary Field: {assoc.acceptor.user_identity.primary}")
            if assoc.acceptor.user_identity.secondary:
                print(f"Response Secondary Field: {assoc.acceptor.user_identity.secondary}")
        else:
            print("No user identity negotiation")

        print("\n----- Association Capabilities -----")
        print(f"Maximum PDU Length: {assoc.acceptor.maximum_length}")
        # Safely handle asynchronous operations which might be a tuple
        try:
            if hasattr(assoc.acceptor, 'asynchronous_operations'):
                async_ops = assoc.acceptor.asynchronous_operations
                if isinstance(async_ops, tuple) and len(async_ops) >= 2:
                    print(f"Asynchronous Operations Window (Invoked): {async_ops[0]}")
                    print(f"Asynchronous Operations Window (Performed): {async_ops[1]}")
                elif hasattr(async_ops, 'maximum_number_invoked') and hasattr(async_ops, 'maximum_number_performed'):
                    print(f"Asynchronous Operations Window (Invoked): {async_ops.maximum_number_invoked}")
                    print(f"Asynchronous Operations Window (Performed): {async_ops.maximum_number_performed}")
                else:
                    print(f"Asynchronous Operations Window: {async_ops}")
            else:
                print("Asynchronous Operations Window: Not negotiated")
        except Exception as e:
            print(f"Asynchronous Operations Window: Error retrieving information - {str(e)}")
        print("================================================\n")

    elif event.event == evt.EVT_REJECTED:
        print("\n===== Association Rejected =====")
        print(f"Rejection Source: {event.reject_source}")
        print(f"Rejection Reason: {event.reject_reason}")
        print("================================\n")

    elif event.event == evt.EVT_RELEASED:
        print("\n===== Association Released =====")
        print(f"Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}")
        print("================================\n")

    elif event.event == evt.EVT_ABORTED:
        print("\n===== Association Aborted =====")
        print(f"Abort Source: {'Remote' if event.source == 'remote' else 'Local'}")
        print(f"Abort Reason: {event.reason}")
        print("===============================\n")

    return 0x0000  # Success

def analyze_association_negotiation(ae, pacs_ip, pacs_port, pacs_ae_title, verbose=False, output_file=None):
    """Analyze the association negotiation process with PACS."""
    global current_association

    # Set up logging if verbose mode is enabled
    if verbose:
        debug_logger()

    # If output file is specified, set up file logging
    if output_file:
        file_handler = logging.FileHandler(output_file)
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        logging.getLogger('pynetdicom').addHandler(file_handler)

    print("\n[*] Analyzing Association Negotiation")
    print(f"[*] Preparing to connect to {pacs_ae_title} at {pacs_ip}:{pacs_port}")

    # Add event handlers for association events
    handlers = [
        (evt.EVT_ESTABLISHED, handle_association_events),
        (evt.EVT_REJECTED, handle_association_events),
        (evt.EVT_RELEASED, handle_association_events),
        (evt.EVT_ABORTED, handle_association_events)
    ]

    # Add extensive presentation contexts to test negotiation
    # Add verification context
    ae.add_requested_context(Verification)

    # Add standard query/retrieve contexts
    ae.add_requested_context(PatientRootQueryRetrieveInformationModelFind)
    ae.add_requested_context(PatientRootQueryRetrieveInformationModelMove)
    ae.add_requested_context(PatientRootQueryRetrieveInformationModelGet)
    ae.add_requested_context(StudyRootQueryRetrieveInformationModelFind)
    ae.add_requested_context(StudyRootQueryRetrieveInformationModelMove)

    # Add storage contexts
    add_storage_presentation_contexts(ae)

    # Print requested contexts
    print("\n[*] Requested Presentation Contexts:")
    for i, context in enumerate(ae.requested_contexts):
        print(f"{i+1}. {context.abstract_syntax.name if hasattr(context.abstract_syntax, 'name') else context.abstract_syntax}")
        for ts in context.transfer_syntax:
            print(f"   - {ts.name if hasattr(ts, 'name') else ts}")

    # Establish association
    print(f"\n[*] Attempting to establish association with {pacs_ae_title}...")
    current_association = ae.associate(pacs_ip, pacs_port, ae_title=pacs_ae_title, evt_handlers=handlers)

    if current_association.is_established:
        print("\n[+] Association established successfully")
        print("[*] Detailed negotiation information has been logged")

        # Print a summary of accepted contexts
        print("\n[*] Summary of Accepted Presentation Contexts:")
        for i, context in enumerate(current_association.accepted_contexts):
            abstract_name = context.abstract_syntax.name if hasattr(context.abstract_syntax, 'name') else context.abstract_syntax
            transfer_name = context.transfer_syntax.name if hasattr(context.transfer_syntax, 'name') else context.transfer_syntax
            print(f"{i+1}. {abstract_name}")
            print(f"   - Using transfer syntax: {transfer_name}")

        # Release the association
        print("\n[*] Releasing association")
        current_association.release()
    else:
        print("\n[-] Association establishment failed")

    print("\n[*] Association negotiation analysis complete")
    if output_file:
        print(f"[*] Detailed log saved to: {output_file}")

def main():
    # Reset global variables at start
    global current_association, operation_cancelled, current_query_model
    current_association = None
    operation_cancelled = False
    current_query_model = None

    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description="DICOM Simulator for Various Requests")
    parser.add_argument("action", choices=['connect', 'echo', 'store', 'find', 'retrieve', 'move-all', 'disconnect', 'analyze-negotiation'],
                        help="Action to perform")
    parser.add_argument("--dicom_folder", default="DICOM_images", help="Folder with DICOM files (for store)")
    parser.add_argument("--pacs_ip", required=True, help="PACS server IP address")
    parser.add_argument("--pacs_port", type=int, required=True, help="PACS server port")
    parser.add_argument("--called_ae_title", required=True, help="Called AE title (remote/server AE title)")
    parser.add_argument("--calling_ae_title", default="MODALITY", help="Calling AE title (local/client AE title)")
    parser.add_argument("--study_uid", help="StudyInstanceUID for retrieve (optional for move-all)")
    parser.add_argument("--output_folder", default="retrieved_images", help="Folder to save retrieved images")
    parser.add_argument("--query_level", choices=["PATIENT", "STUDY", "SERIES", "IMAGE"], default="PATIENT",
                        help="Specify the query level for C-FIND (default is 'PATIENT')")
    parser.add_argument("--retrieve_method", choices=["get", "move"], default="move",
                        help="Specify the retrieval method (C-GET or C-MOVE)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output for debugging")
    parser.add_argument("--log_file", help="Output file for detailed logging (for analyze-negotiation)")
    args = parser.parse_args()

    # Configure the Application Entity with the calling AE title
    ae = AE(ae_title=args.calling_ae_title)

    # Add verification context
    ae.add_requested_context(Verification)

    # Add storage contexts based on the action
    if args.action == 'store':
        print("[*] Adding storage presentation contexts")
        add_storage_presentation_contexts(ae)
    elif args.action == 'find':
        ae.add_requested_context(PatientRootQueryRetrieveInformationModelFind)
    elif args.action in ['retrieve', 'move-all']:
        if args.retrieve_method == "get":
            ae.add_requested_context(PatientRootQueryRetrieveInformationModelGet)
        else:
            ae.add_requested_context(PatientRootQueryRetrieveInformationModelMove)
        add_storage_presentation_contexts(ae)

    if args.action == 'connect':
        print(f"[*] Trying to establish association...")
        print(f"[*] Calling AE Title (local): {args.calling_ae_title}")
        print(f"[*] Called AE Title (remote): {args.called_ae_title}")
        current_association = ae.associate(args.pacs_ip, args.pacs_port, ae_title=args.called_ae_title)
        if current_association.is_established:
            print("[+] Association established successfully.")
            current_association.release()
            print("[*] Association released.")
        else:
            print("[-] Association rejected by remote AE.")
            print(f"[-] This could be because:")
            print(f"    - The AE title '{args.called_ae_title}' is not recognized")
            print(f"    - The PACS server only accepts connections from specific AE titles")
            print(f"    - Network connectivity issues")
            print(f"    - Invalid PACS configuration")
    elif args.action == 'echo':
        print("[*] Starting C-ECHO operation (press Ctrl+C to attempt cancellation, though C-ECHO operations usually complete too quickly to cancel)")
        send_c_echo(ae, args.pacs_ip, args.pacs_port, args.called_ae_title)
    elif args.action == 'store':
        print("[*] Starting C-STORE operation")
        send_c_store(ae, args.dicom_folder, args.pacs_ip, args.pacs_port, args.called_ae_title)
    elif args.action == 'find':
        print("[*] Starting C-FIND operation (press Ctrl+C to send C-CANCEL)")
        send_c_find(ae, args.pacs_ip, args.pacs_port, args.called_ae_title, query_level=args.query_level)
    elif args.action == 'retrieve':
        if not args.study_uid:
            print("Error: --study_uid is required for retrieval.")
            return
        if args.retrieve_method == "get":
            print("[*] Starting C-GET operation (press Ctrl+C to send C-CANCEL)")
            send_c_get(ae, args.pacs_ip, args.pacs_port, args.called_ae_title, args.study_uid, args.output_folder)
        else:
            print("[*] Starting C-MOVE operation (press Ctrl+C to send C-CANCEL)")
            send_c_move(ae, args.pacs_ip, args.pacs_port, args.called_ae_title, args.study_uid, args.output_folder)
    elif args.action == 'move-all':
        print("[*] Starting MOVE ALL STUDIES operation (press Ctrl+C to send C-CANCEL)")
        print("[*] WARNING: This operation will retrieve ALL studies from the PACS server.")
        print("[*] This may take a long time and use significant disk space.")
        send_all_studies_move(ae, args.pacs_ip, args.pacs_port, args.called_ae_title, args.output_folder)
    elif args.action == 'analyze-negotiation':
        print("[*] Starting Association Negotiation Analysis")
        analyze_association_negotiation(ae, args.pacs_ip, args.pacs_port, args.called_ae_title,
                                       verbose=args.verbose, output_file=args.log_file)
    elif args.action == 'disconnect':
        print("Disconnecting (simulated).")

if __name__ == "__main__":
    main()
