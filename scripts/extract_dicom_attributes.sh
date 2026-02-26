#!/bin/bash
# Script to extract unique DICOM attribute values from pcap files
# Shows unique values with frequency counts
# Usage: ./extract_dicom_attributes.sh [pcap_file]
#   If pcap_file is given, only process that file.
#   Otherwise, process all pcap files in PCAP_DIR.

PCAP_DIR="/home/strongcourage/pcaps/intact/DICOMpcaps"
OUTPUT_DIR="/home/strongcourage/NetworkFuzzer/extracted_data"
NETWORKFUZZER="./networkfuzzer"
TIMEOUT_SEC=300  # Timeout per extraction command (5 min for large files)

# All available DICOM attributes from MMT-DPI
DICOM_ATTRIBUTES=(
    "pdu_type"
    "pdu_len"
    "proto_version"
    "called_ae_title"
    "calling_ae_title"
    "application_context"
    "presentation_context"
    "max_pdu_length"
    "implementation_class_uid"
    "pdv_length"
    "pdv_context"
    "pdv_flags"
    "command_group_length"
    "command_field"
    "patient_name"
    "status"
    "affected_sop_class_uid"
    "message_id"
    "abstract_syntax"
    "transfer_syntax"
    "data_set_type"
)

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Function to sanitize filename
sanitize_filename() {
    echo "$1" | sed 's/[^a-zA-Z0-9._-]/_/g'
}

# Function to extract attributes from a single pcap
extract_from_pcap() {
    local pcap_file="$1"
    local pcap_name=$(basename "$pcap_file")
    local safe_name=$(sanitize_filename "${pcap_name%.*}")
    local output_file="$OUTPUT_DIR/${safe_name}_unique_values.txt"

    echo "=============================================="
    echo "Processing: $pcap_name"
    echo "Output: $output_file"
    echo "=============================================="

    # Create output file header
    {
        echo "========================================"
        echo "DICOM Attribute Extraction: $pcap_name"
        echo "Extracted: $(date)"
        echo "========================================"
        echo ""
    } > "$output_file"

    # Extract DICOM attributes
    for attr in "${DICOM_ATTRIBUTES[@]}"; do
        printf "  Extracting dicom.%-25s " "$attr..."

        # Run with timeout
        result=$(timeout ${TIMEOUT_SEC}s $NETWORKFUZZER extract -t "$pcap_file" -p dicom -a "$attr" 2>/dev/null | tail -n +2)

        if [ $? -eq 124 ]; then
            echo "[TIMEOUT]"
            echo "dicom.$attr: [TIMEOUT]" >> "$output_file"
            echo "" >> "$output_file"
            continue
        fi

        if [ -z "$result" ]; then
            echo "[no data]"
            continue
        fi

        # Extract values (column 2+), count unique values
        values=$(echo "$result" | awk '{$1=""; print $0}' | sed 's/^ *//')
        total_count=$(echo "$values" | wc -l)
        unique_values=$(echo "$values" | sort | uniq -c | sort -rn)
        unique_count=$(echo "$unique_values" | wc -l)

        echo "[$total_count total, $unique_count unique]"

        # Write to output file
        {
            echo "----------------------------------------"
            echo "dicom.$attr"
            echo "  Total packets: $total_count"
            echo "  Unique values: $unique_count"
            echo "  Values (count | value):"
            echo "$unique_values" | head -50 | while read count val; do
                printf "    %6d | %s\n" "$count" "$val"
            done
            if [ $unique_count -gt 50 ]; then
                echo "    ... and $((unique_count - 50)) more unique values"
            fi
            echo ""
        } >> "$output_file"
    done

    echo ""
    echo "  Results saved to: $output_file"
    echo ""
}

# Main execution
echo ""
echo "========================================================"
echo "  DICOM Unique Value Extractor for NetworkFuzzer"
echo "========================================================"
echo "PCAP Directory: $PCAP_DIR"
echo "Output Directory: $OUTPUT_DIR"
echo "Timeout per extraction: ${TIMEOUT_SEC}s"
echo ""

# If a specific pcap file is provided as argument, use only that file
if [ -n "$1" ]; then
    if [ ! -f "$1" ]; then
        echo "ERROR: File not found: $1"
        exit 1
    fi
    pcap_files="$1"
else
    # Check if directory exists
    if [ ! -d "$PCAP_DIR" ]; then
        echo "ERROR: Directory not found: $PCAP_DIR"
        exit 1
    fi

    # Find all pcap files
    pcap_files=$(find "$PCAP_DIR" -type f \( -name "*.pcap" -o -name "*.pcapng" \) 2>/dev/null | sort)

    if [ -z "$pcap_files" ]; then
        echo "No pcap files found in $PCAP_DIR"
        exit 1
    fi
fi

file_count=$(echo "$pcap_files" | wc -l)
echo "Found $file_count pcap file(s) to process"
echo ""

# Process each pcap file
current=0
while IFS= read -r pcap_file; do
    current=$((current + 1))
    echo "[$current/$file_count]"
    extract_from_pcap "$pcap_file"
done <<< "$pcap_files"

echo ""
echo "========================================================"
echo "  Extraction Complete!"
echo "========================================================"
echo ""
echo "Output files:"
ls -lh "$OUTPUT_DIR"/*.txt 2>/dev/null
