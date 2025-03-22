import os
import subprocess
import sys

def process_single_pcap(pcap_path, output_path=None):
    """
    Process a single .pcap file, generating a corresponding .csv file using cicflowmeter.

    Args:
        pcap_path (str): Path to the .pcap file.
        output_path (str, optional): Path for the output CSV file. If None, uses the same path as the input with .csv extension.

    Returns:
        bool: True if processing was successful, False otherwise.
    """
    # Ensure the input file exists
    if not os.path.exists(pcap_path):
        print(f"Error: The file '{pcap_path}' does not exist.")
        return False

    # Ensure the file is a .pcap file
    if not pcap_path.endswith(".pcap"):
        print(f"Error: The file '{pcap_path}' is not a .pcap file.")
        return False

    # Determine output CSV path
    if output_path is None:
        csv_path = os.path.splitext(pcap_path)[0] + ".csv"
    else:
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
        print(f"Processing: {pcap_path} -> {csv_path}")
        subprocess.run([
            "cicflowmeter",
            "-f", pcap_path,
            "-c", csv_path
        ], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error processing {pcap_path}: {e}")
        return False

def process_pcap_files(input_folder, output_folder=None):
    """
    Process all .pcap files in the given folder and its subfolders,
    generating corresponding .csv files using cicflowmeter.

    Args:
        input_folder (str): Path to the folder containing .pcap files.
        output_folder (str, optional): Directory to store output CSV files. If None, CSV files are placed alongside PCAP files.
    """
    # Ensure the input folder exists
    if not os.path.exists(input_folder):
        print(f"Error: The folder '{input_folder}' does not exist.")
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

                    process_single_pcap(pcap_path, output_path)
                else:
                    # Use the default behavior
                    process_single_pcap(pcap_path)

if __name__ == "__main__":
    # Check command line arguments
    if len(sys.argv) < 2:
        print("Usage:")
        print("  To process a directory: python process_pcaps.py -d <input_folder> [-o <output_folder>]")
        print("  To process a single file: python process_pcaps.py -f <input_file> [-o <output_file>]")
        print("  For backward compatibility: python process_pcaps.py <input_folder_or_file>")
        sys.exit(1)

    # Parse arguments
    input_path = None
    output_path = None
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
        process_single_pcap(input_path, output_path)
    elif is_dir:
        if not os.path.isdir(input_path):
            print(f"Error: The directory '{input_path}' does not exist.")
            sys.exit(1)
        process_pcap_files(input_path, output_path)
    else:
        print("Error: Invalid input path or option.")
        print("Usage:")
        print("  To process a directory: python process_pcaps.py -d <input_folder> [-o <output_folder>]")
        print("  To process a single file: python process_pcaps.py -f <input_file> [-o <output_file>]")
        print("  For backward compatibility: python process_pcaps.py <input_folder_or_file>")
        sys.exit(1)
