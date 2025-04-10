import os
import subprocess
import sys
import shutil
import csv
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("process_pcaps.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# List of DICOM fields to extract with tshark
DICOM_FIELDS = [
    "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
    "dicom.pdu.type", "dicom.pdu.len", "dicom.assoc.version",
    "dicom.assoc.ae.called", "dicom.assoc.ae.calling",
    "dicom.assoc.reject.result", "dicom.assoc.reject.source", "dicom.assoc.reject.reason",
    "dicom.assoc.abort.source", "dicom.assoc.abort.reason",
    "dicom.assoc.item.type", "dicom.assoc.item.len", "dicom.actx",
    "dicom.pctx.id", "dicom.pctx.result", "dicom.pctx.abss.syntax", "dicom.pctx.xfer.syntax",
    "dicom.userinfo.uid", "dicom.userinfo.version", "dicom.userinfo.extneg.sopclassuid",
    "dicom.userinfo.extneg.relational", "dicom.userinfo.extneg.datetimematching",
    "dicom.userinfo.extneg.fuzzymatching", "dicom.userinfo.extneg.timezone",
    "dicom.userinfo.rolesel.sopclassuid", "dicom.userinfo.rolesel.scurole",
    "dicom.userinfo.rolesel.scprole", "dicom.userinfo.asyncneg.maxnumopsinv",
    "dicom.userinfo.asyncneg.maxnumopsper", "dicom.userinfo.user_identify.type",
    "dicom.userinfo.user_identify.response_requested", "dicom.userinfo.user_identify.primary_field",
    "dicom.userinfo.user_identify.secondary_field", "dicom.max_pdu_len", "dicom.pdv.len",
    "dicom.pdv.ctx", "dicom.pdv.flags", "dicom.tag", "dicom.tag.vr", "dicom.tag.vl",
    "dicom.tag.value.str"
]

def process_single_pcap_cicflowmeter(pcap_path, output_path=None):
    """
    Process a single .pcap file using cicflowmeter, generating a corresponding .csv file.

    Args:
        pcap_path (str): Path to the .pcap file.
        output_path (str, optional): Path for the output CSV file. If None, uses the same path as the input with .csv extension.

    Returns:
        bool: True if processing was successful, False otherwise.
    """
    # Convert to absolute paths to avoid issues
    pcap_path = os.path.abspath(pcap_path)

    # Determine output CSV path
    if output_path is None:
        csv_path = os.path.splitext(pcap_path)[0] + ".csv"
    else:
        output_path = os.path.abspath(output_path)
        if os.path.isdir(output_path):
            # If output is a directory, use the original filename with .csv extension in that directory
            filename = os.path.basename(os.path.splitext(pcap_path)[0]) + ".csv"
            csv_path = os.path.join(output_path, filename)
        else:
            # Use the exact output path specified
            csv_path = output_path

    # Create output directory if it doesn't exist
    output_dir = os.path.dirname(csv_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Run the cicflowmeter command to process the .pcap file
    try:
        logger.info(f"Processing with cicflowmeter: {pcap_path} -> {csv_path}")
        subprocess.run([
            "cicflowmeter",
            "-f", pcap_path,
            "-c", csv_path
        ], check=True)
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Error processing {pcap_path} with cicflowmeter: {e}")
        return False

def process_single_pcap_zeek(pcap_path, output_path=None):
    """
    Process a single .pcap file using Zeek, collecting conn.log and renaming it.
    Also converts the conn.log to CSV format.

    Args:
        pcap_path (str): Path to the .pcap file.
        output_path (str, optional): Path for the output log file. If None, uses the same path as the input with .log extension.

    Returns:
        bool: True if processing was successful, False otherwise.
    """
    # Convert to absolute paths to avoid issues when changing directories
    pcap_path = os.path.abspath(pcap_path)

    # Create a temporary directory to store Zeek logs
    pcap_name = os.path.splitext(os.path.basename(pcap_path))[0]
    temp_dir = os.path.join(os.path.dirname(pcap_path), f"zeek_logs_{pcap_name}")

    # Determine output paths
    if output_path is None:
        log_path = os.path.splitext(pcap_path)[0] + ".log"
        csv_path = os.path.splitext(pcap_path)[0] + ".csv"
    else:
        output_path = os.path.abspath(output_path)
        if os.path.isdir(output_path):
            # If output is a directory, use the original filename in that directory
            filename_base = os.path.basename(os.path.splitext(pcap_path)[0])
            log_path = os.path.join(output_path, filename_base + ".log")
            csv_path = os.path.join(output_path, filename_base + ".csv")
        else:
            # Use the exact output path specified for log, and derive CSV path
            log_path = output_path
            # If output_path has an extension, replace it with .csv, otherwise append .csv
            output_basename = os.path.basename(output_path)
            if '.' in output_basename and not output_path.endswith('/'):
                # Replace the extension with .csv
                csv_path = os.path.join(os.path.dirname(output_path),
                                       os.path.splitext(output_basename)[0] + '.csv')
            else:
                # Just append .csv if no extension or if it's a directory
                csv_path = output_path + '.csv'

    # Create output directory if it doesn't exist
    output_dir = os.path.dirname(log_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Create temporary directory for Zeek logs if it doesn't exist
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)

    try:
        # Change to the temporary directory
        original_dir = os.getcwd()
        os.chdir(temp_dir)

        # Add -C flag to ignore checksums based on the warning message
        logger.info(f"Processing with Zeek: {pcap_path}")
        subprocess.run([
            "/usr/local/zeek/bin/zeek",
            "-C",  # Ignore checksums
            "-r", pcap_path
        ], check=True)

        # Check if conn.log was generated
        if os.path.exists("conn.log"):
            # Move and rename conn.log to the output path
            shutil.copy("conn.log", log_path)
            logger.info(f"Zeek conn.log copied to: {log_path}")

            # Process the conn.log to CSV
            logger.info(f"Converting conn.log to CSV: {csv_path}")

            # Initialize variables
            fields = []  # Column headers
            data_rows = []  # Rows of data

            # Process the conn.log file
            with open("conn.log", "r") as log_file:
                for line in log_file:
                    # Skip metadata lines starting with "#"
                    if line.startswith("#"):
                        # Extract column headers from the "#fields" line
                        if line.startswith("#fields"):
                            fields = line.strip().split("\x09")[1:]  # Skip "#fields"
                        continue

                    # Process actual data rows
                    row = line.strip().split("\x09")
                    data_rows.append(row)

            # Write the extracted data to a CSV file
            with open(csv_path, "w", newline="") as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow(fields)  # Write headers
                writer.writerows(data_rows)  # Write rows

            logger.info(f"CSV file generated: {csv_path}")

            # Clean up
            os.chdir(original_dir)
            shutil.rmtree(temp_dir)
            return True
        else:
            logger.error(f"Error: Zeek did not generate conn.log for {pcap_path}")
            os.chdir(original_dir)
            shutil.rmtree(temp_dir)
            return False

    except subprocess.CalledProcessError as e:
        logger.error(f"Error processing {pcap_path} with Zeek: {e}")
        os.chdir(original_dir)
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        return False
    except Exception as e:
        logger.error(f"Unexpected error processing {pcap_path} with Zeek: {e}")
        os.chdir(original_dir)
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        return False

def process_single_pcap_tshark(pcap_path, output_path=None):
    """
    Process a single .pcap file using tshark, extracting DICOM fields to a CSV file.

    Args:
        pcap_path (str): Path to the .pcap file.
        output_path (str, optional): Path for the output CSV file. If None, uses the same path as the input with .csv extension.

    Returns:
        bool: True if processing was successful, False otherwise.
    """
    # Convert to absolute paths to avoid issues
    pcap_path = os.path.abspath(pcap_path)

    # Determine output CSV path
    if output_path is None:
        csv_path = os.path.splitext(pcap_path)[0] + "_dicom.csv"
    else:
        output_path = os.path.abspath(output_path)
        if os.path.isdir(output_path):
            # If output is a directory, use the original filename with _dicom.csv extension in that directory
            filename = os.path.basename(os.path.splitext(pcap_path)[0]) + "_dicom.csv"
            csv_path = os.path.join(output_path, filename)
        else:
            # Use the exact output path specified
            csv_path = output_path

    # Create output directory if it doesn't exist
    output_dir = os.path.dirname(csv_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Run the tshark command to extract DICOM fields
    try:
        logger.info(f"Processing with tshark: {pcap_path} -> {csv_path}")

        # Build the command with all DICOM fields
        fields_args = sum([["-e", field] for field in DICOM_FIELDS], [])
        command = [
            "tshark", "-r", pcap_path, "-Y", "dicom", "-T", "fields",
            "-E", "separator=,", "-E", "quote=d", "-E", "header=y"
        ] + fields_args

        # Run the command and write output to the CSV file
        with open(csv_path, "w") as f:
            subprocess.run(command, stdout=f, check=True)

        logger.info(f"CSV file generated: {csv_path}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Error processing {pcap_path} with tshark: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error processing {pcap_path} with tshark: {e}")
        return False

def process_single_pcap(pcap_path, output_path=None, mode="cicflowmeter"):
    """
    Process a single .pcap file, generating output based on the selected mode.

    Args:
        pcap_path (str): Path to the .pcap file.
        output_path (str, optional): Path for the output file. If None, uses the same path as the input with appropriate extension.
        mode (str): Processing mode - 'cicflowmeter', 'zeek', or 'tshark'.

    Returns:
        bool: True if processing was successful, False otherwise.
    """
    # Ensure the input file exists
    if not os.path.exists(pcap_path):
        logger.error(f"Error: The file '{pcap_path}' does not exist.")
        return False

    # Ensure the file is a .pcap file
    if not pcap_path.endswith(".pcap"):
        logger.error(f"Error: The file '{pcap_path}' is not a .pcap file.")
        return False

    # Process based on mode
    if mode.lower() == "cicflowmeter":
        return process_single_pcap_cicflowmeter(pcap_path, output_path)
    elif mode.lower() == "zeek":
        return process_single_pcap_zeek(pcap_path, output_path)
    elif mode.lower() == "tshark":
        return process_single_pcap_tshark(pcap_path, output_path)
    else:
        logger.error(f"Error: Unsupported mode '{mode}'. Use 'cicflowmeter', 'zeek', or 'tshark'.")
        return False

def process_pcap_files(input_folder, output_folder=None, mode="cicflowmeter"):
    """
    Process all .pcap files in the given folder and its subfolders.

    Args:
        input_folder (str): Path to the folder containing .pcap files.
        output_folder (str, optional): Directory to store output files. If None, files are placed alongside PCAP files.
        mode (str): Processing mode - 'cicflowmeter', 'zeek', or 'tshark'.
    """
    # Ensure the input folder exists
    if not os.path.exists(input_folder):
        logger.error(f"Error: The folder '{input_folder}' does not exist.")
        return

    # Create output directory if specified and doesn't exist
    if output_folder and not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Walk through all subdirectories and files in the folder
    for root, _, files in os.walk(input_folder):
        for file in files:
            if file.endswith(".pcap"):
                pcap_path = os.path.join(root, file)

                if output_folder:
                    # If output folder is specified, create a corresponding folder structure
                    rel_path = os.path.relpath(root, input_folder)
                    if rel_path == ".":
                        # File is in the root input folder
                        output_path = output_folder
                    else:
                        # File is in a subfolder, preserve the structure
                        output_path = os.path.join(output_folder, rel_path)

                    if not os.path.exists(output_path):
                        os.makedirs(output_path)

                    process_single_pcap(pcap_path, output_path, mode)
                else:
                    # Use the default behavior
                    process_single_pcap(pcap_path, None, mode)

if __name__ == "__main__":
    # Check command line arguments
    if len(sys.argv) < 2 or sys.argv[1] == "-h" or sys.argv[1] == "--help":
        print("PCAP Processing Tool - Convert PCAP files to structured formats")
        print("\nUsage:")
        print("  To process a directory: python process_pcaps.py -d <input_folder> [-o <output_folder>] [-m <mode>]")
        print("  To process a single file: python process_pcaps.py -f <input_file> [-o <output_file>] [-m <mode>]")
        print("  For backward compatibility: python process_pcaps.py <input_folder_or_file>")
        print("\nOptions:")
        print("  -f <input_file>      Specify a single PCAP file to process")
        print("  -d <input_folder>    Specify a directory containing PCAP files to process")
        print("  -o <output>          Specify an output file or directory for results")
        print("  -m <mode>            Specify the processing mode (default: cicflowmeter)")
        print("  -h, --help           Show this help message and exit")
        print("\nProcessing Modes:")
        print("  cicflowmeter         Process PCAP files using cicflowmeter, outputs CSV files")
        print("  zeek                 Process PCAP files using Zeek, outputs both LOG and CSV files")
        print("  tshark               Process PCAP files using tshark, extracts DICOM fields to CSV")
        print("\nExamples:")
        print("  python process_pcaps.py -f capture.pcap -m zeek -o results.log")
        print("  python process_pcaps.py -d pcap_collection/ -o output_folder/ -m cicflowmeter")
        print("  python process_pcaps.py -f dicom_capture.pcap -m tshark -o dicom_features.csv")
        sys.exit(1)

    # Parse arguments
    input_path = None
    output_path = None
    mode = "cicflowmeter"  # Default mode
    is_file = False
    is_dir = False

    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == "-f":
            if i + 1 < len(sys.argv):
                input_path = sys.argv[i + 1]
                is_file = True
                i += 2
            else:
                print("Error: Missing path after -f")
                sys.exit(1)
        elif sys.argv[i] == "-d":
            if i + 1 < len(sys.argv):
                input_path = sys.argv[i + 1]
                is_dir = True
                i += 2
            else:
                print("Error: Missing path after -d")
                sys.exit(1)
        elif sys.argv[i] == "-o":
            if i + 1 < len(sys.argv):
                output_path = sys.argv[i + 1]
                i += 2
            else:
                print("Error: Missing path after -o")
                sys.exit(1)
        elif sys.argv[i] == "-m":
            if i + 1 < len(sys.argv):
                mode = sys.argv[i + 1].lower()
                if mode not in ["cicflowmeter", "zeek", "tshark"]:
                    print(f"Error: Unsupported mode '{mode}'. Use 'cicflowmeter', 'zeek', or 'tshark'.")
                    sys.exit(1)
                i += 2
            else:
                print("Error: Missing mode after -m")
                sys.exit(1)
        else:
            # For backward compatibility
            if input_path is None:
                input_path = sys.argv[i]
                # Determine if it's a file or directory for backward compatibility
                if os.path.isdir(input_path):
                    is_dir = True
                elif os.path.isfile(input_path) and input_path.endswith(".pcap"):
                    is_file = True
                else:
                    print("Error: The provided path is neither a valid directory nor a .pcap file.")
                    sys.exit(1)
            i += 1

    # Process the inputs
    if input_path is None:
        print("Error: No input path specified.")
        sys.exit(1)

    if is_file:
        if not os.path.isfile(input_path):
            print(f"Error: The file '{input_path}' does not exist.")
            sys.exit(1)
        process_single_pcap(input_path, output_path, mode)
    elif is_dir:
        if not os.path.isdir(input_path):
            print(f"Error: The directory '{input_path}' does not exist.")
            sys.exit(1)
        process_pcap_files(input_path, output_path, mode)
    else:
        print("Error: Invalid input path or option.")
        print("Usage:")
        print("  To process a directory: python process_pcaps.py -d <input_folder> [-o <output_folder>] [-m <mode>]")
        print("  To process a single file: python process_pcaps.py -f <input_file> [-o <output_file>] [-m <mode>]")
        print("  For backward compatibility: python process_pcaps.py <input_folder_or_file>")
        print("  Modes: 'cicflowmeter' (default), 'zeek', or 'tshark'")
        sys.exit(1)
