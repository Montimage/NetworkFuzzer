#!/usr/bin/env python3
"""
DICOM Patient Name Fuzzing Script

This script systematically tries different patient names with networkfuzzer
to find a patient name that returns search results from the DICOM server.
"""

import os
import re
import subprocess
import shutil
import time
import logging
import sys
import glob
from datetime import datetime

# Configuration
PCAP_FILE = "../new_captured_patient.pcap"
RULE_FILE = "rules/41.dicom_update_patient_name.xml"
TEMP_RULE_FILE = "temp_rule_41.xml"
RESULTS_FILE = "fuzzing_results.txt"
TEMP_PATIENT_NAME_FILE = "/tmp/dicom_patient_name"

# Clear the results file at the start
with open(RESULTS_FILE, 'w') as f:
    f.write(f"DICOM Patient Name Fuzzing Results - Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f.write("=" * 80 + "\n\n")

# Set up logging to both file and terminal
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("fuzzing.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Also log to the results file
results_handler = logging.FileHandler(RESULTS_FILE)
results_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(results_handler)

def check_for_temp_files():
    """Check for any temporary files that might be affecting the patient name."""
    logger.info("Checking for temporary files that might affect patient name...")

    # Check for /tmp/dicom_patient_name
    if os.path.exists(TEMP_PATIENT_NAME_FILE):
        with open(TEMP_PATIENT_NAME_FILE, 'r') as f:
            content = f.read().strip()
            logger.info(f"Found {TEMP_PATIENT_NAME_FILE} with content: '{content}'")

    # Check for other potential files
    temp_files = glob.glob("/tmp/dicom_*")
    for file in temp_files:
        if file != TEMP_PATIENT_NAME_FILE:
            try:
                with open(file, 'r') as f:
                    content = f.read().strip()
                    logger.info(f"Found {file} with content: '{content}'")
            except:
                logger.info(f"Found {file} but couldn't read its content")

def create_rule_file(patient_name):
    """Create a new rule file with the specified patient name."""
    try:
        # Read the original rule file
        with open(RULE_FILE, 'r') as file:
            content = file.read()

        # Replace the patient name in the rule file
        pattern = r'(char \*new_val = ")[^"]*(")'
        replacement = f'\\1{patient_name}\\2'
        updated_content = re.sub(pattern, replacement, content)

        # Check if the replacement was successful
        if updated_content == content:
            logger.error(f"Failed to replace patient name in rule file. Pattern not found.")
            return False

        # Write the updated content to a new rule file
        with open(TEMP_RULE_FILE, 'w') as file:
            file.write(updated_content)

        # Verify the update by reading the file again
        with open(TEMP_RULE_FILE, 'r') as file:
            verify_content = file.read()

        # Check if the patient name was correctly updated
        if patient_name not in verify_content:
            logger.error(f"Verification failed: Patient name '{patient_name}' not found in new rule file.")
            return False

        logger.info(f"Created new rule file with patient name: {patient_name}")
        logger.info(f"New rule file content:")
        logger.info("-" * 50)
        logger.info(verify_content)
        logger.info("-" * 50)

        # Also update the temporary file if it exists
        if os.path.exists(TEMP_PATIENT_NAME_FILE):
            with open(TEMP_PATIENT_NAME_FILE, 'w') as f:
                f.write(patient_name)
            logger.info(f"Updated {TEMP_PATIENT_NAME_FILE} with patient name: {patient_name}")
        else:
            # Create the temporary file if it doesn't exist
            with open(TEMP_PATIENT_NAME_FILE, 'w') as f:
                f.write(patient_name)
            logger.info(f"Created {TEMP_PATIENT_NAME_FILE} with patient name: {patient_name}")

        # Add a small delay to ensure the file is properly written
        time.sleep(1)

        return True
    except Exception as e:
        logger.error(f"Error creating rule file: {e}")
        return False

def compile_rule_file():
    """Compile the rule file to generate a new .so file."""
    try:
        logger.info("Compiling rule file...")

        # Construct the compile command
        compile_cmd = f"./networkfuzzer compile rules/41.dicom_update_patient_name.so {TEMP_RULE_FILE}"

        # Run the compile command
        result = subprocess.run(
            compile_cmd,
            shell=True,
            capture_output=True,
            text=True,
            check=False
        )

        # Check if compilation was successful
        if result.returncode != 0:
            logger.error(f"Failed to compile rule file: {result.stderr}")
            return False

        logger.info("Rule file compiled successfully")
        logger.info("Compilation output:")
        logger.info("-" * 50)
        logger.info(result.stdout)
        logger.info("-" * 50)

        # Add a small delay to ensure the file is properly written
        time.sleep(1)

        return True
    except Exception as e:
        logger.error(f"Error compiling rule file: {e}")
        return False

def run_networkfuzzer():
    """Run networkfuzzer and return the output."""
    try:
        logger.info("Running networkfuzzer...")

        # First, verify the rule file content before running networkfuzzer
        with open(TEMP_RULE_FILE, 'r') as file:
            rule_content = file.read()
            logger.info("Rule file content before running networkfuzzer:")
            logger.info("-" * 50)
            logger.info(rule_content)
            logger.info("-" * 50)

        # Construct the command
        fuzzer_cmd = f"sudo ./networkfuzzer replay -A -t {PCAP_FILE} -Xforward.default=FORWARD -Xengine.exclude-rules=\"1-40,42-1000\" -Xforward.nb-copies=1"

        # Run networkfuzzer with a fresh process
        result = subprocess.run(
            fuzzer_cmd,
            shell=True,
            capture_output=True,
            text=True,
            check=False
        )
        output = result.stdout + result.stderr

        # Print the output for debugging
        logger.info("Networkfuzzer output:")
        logger.info("-" * 50)
        logger.info(output)
        logger.info("-" * 50)

        return output
    except Exception as e:
        logger.error(f"Error running networkfuzzer: {e}")
        return ""

def check_for_results(output):
    """Check if patient results were found in the output."""
    # Look specifically for the exact phrase indicating patient search results
    if "[+] Patient search results were found!" in output:
        logger.info("Found exact indicator of patient search results: '[+] Patient search results were found!'")
        return True

    # If we didn't find the exact phrase, check the DICOM FUZZING SUMMARY section
    if "DICOM FUZZING SUMMARY" in output:
        # Extract the summary section
        summary_match = re.search(r"DICOM FUZZING SUMMARY.*?(?=\n\n|\Z)", output, re.DOTALL)
        if summary_match:
            summary = summary_match.group(0)
            logger.info(f"DICOM FUZZING SUMMARY found: {summary}")

            # Check if the summary contains the exact phrase
            if "[+] Patient search results were found!" in summary:
                logger.info("Patient search results found in summary section")
                return True
            else:
                logger.info("No patient search results found in summary section")

    logger.info("No patient search results found in output")
    return False

def save_result(patient_name, found_results):
    """Save the fuzzing result to the results file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    result = "FOUND" if found_results else "NOT FOUND"

    with open(RESULTS_FILE, 'a') as file:
        file.write(f"{timestamp} - Patient name '{patient_name}' - Results {result}\n")

def fuzz_patient_names():
    """Main function to fuzz patient names."""
    logger.info("Starting DICOM patient name fuzzing...")

    # Create a backup of the original rule file
    shutil.copy2(RULE_FILE, f"{RULE_FILE}.bak")
    logger.info(f"Created backup of rule file: {RULE_FILE}.bak")

    # Try each letter from A to Z
    for letter in range(ord('A'), ord('Z') + 1):
        patient_name = f"{chr(letter)}????????"
        logger.info(f"Trying patient name: {patient_name}")

        # Create a new rule file with the current patient name
        if not create_rule_file(patient_name):
            logger.error(f"Failed to create rule file with patient name {patient_name}, skipping...")
            continue

        # Compile the rule file
        if not compile_rule_file():
            logger.error(f"Failed to compile rule file with patient name {patient_name}, skipping...")
            continue

        # Run networkfuzzer and capture output
        output = run_networkfuzzer()

        # Check if patient results were found
        found_results = check_for_results(output)

        # Save the result
        save_result(patient_name, found_results)

        if found_results:
            logger.info(f"SUCCESS! Found working patient name: {patient_name}")
            return patient_name
        else:
            logger.info(f"No results found with patient name: {patient_name}")

    logger.warning("No working patient name found after trying all letters A-Z")
    return None

def restore_original_rule():
    """Restore the original rule file."""
    try:
        shutil.copy2(f"{RULE_FILE}.bak", RULE_FILE)
        logger.info("Restored original rule file")

        # Clean up the temporary rule file
        if os.path.exists(TEMP_RULE_FILE):
            os.remove(TEMP_RULE_FILE)
            logger.info(f"Removed temporary rule file: {TEMP_RULE_FILE}")
    except Exception as e:
        logger.error(f"Error restoring original rule file: {e}")

def main():
    """Main entry point for the script."""
    logger.info("DICOM Patient Name Fuzzer")
    logger.info("=========================")

    try:
        # Run the fuzzing process
        working_name = fuzz_patient_names()

        if working_name:
            logger.info(f"Fuzzing complete. Working patient name: {working_name}")
            logger.info(f"Results saved to {RESULTS_FILE}")
        else:
            logger.info("Fuzzing complete. No working patient name found.")
            logger.info(f"Results saved to {RESULTS_FILE}")
    finally:
        # Always restore the original rule file
        restore_original_rule()

if __name__ == "__main__":
    main()