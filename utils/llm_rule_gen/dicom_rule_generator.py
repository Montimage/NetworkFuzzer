#!/usr/bin/env python3
# Add dotenv import to load .env file
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

import os
import argparse
import openai
import re
import sys
from typing import Optional

# Example rule template to use as a basis for generation
EXAMPLE_RULE = """
<beginning>
<!-- Property 32: Modify the PDU length to be inconsistent with actual payload -->
<embedded_functions><![CDATA[
    static void em_modify_dicom_pdu_len(
        const rule_info_t *rule, int verdict, uint64_t timestamp,
        uint64_t counter, const mmt_array_t * const trace) {
        int is_string = 0;
        int new_val = 10000;  // Set PDU length to 10000 bytes
        // Replace PDU length field (attribute ID 2 in protocol 701)
        replace_dicom_attribute(701, 2, &new_val, is_string);
        forward_packet();
    }
]]></embedded_functions>
<property property_id="32" type_property="FORWARD"
        description="Modify DICOM PDU length to invalid value (10000)"
        if_satisfied="em_modify_dicom_pdu_len">
    <event description="Got any DICOM packets"
        boolean_expression="((dicom.pdu_type &gt; 0) &amp;&amp; (dicom.pdu_type &lt; 8))"/>
</property>
</beginning>
"""

# Common DICOM attribute information
DICOM_ATTRIBUTES = {
    "pdu_type": {
        "id": 1,
        "description": "PDU Type",
        "values": {
            "A-ASSOCIATE-RQ": 1,
            "A-ASSOCIATE-AC": 2,
            "A-ASSOCIATE-RJ": 3,
            "P-DATA-TF": 4,
            "A-RELEASE-RQ": 5,
            "A-RELEASE-RP": 6,
            "A-ABORT": 7
        }
    },
    "pdu_len": {"id": 2, "description": "PDU Length"},
    "proto_version": {"id": 3, "description": "Protocol Version"},
    "called_ae_title": {"id": 4, "description": "Called AE Title", "is_string": 1},
    "calling_ae_title": {"id": 5, "description": "Calling AE Title", "is_string": 1},
    "application_context": {"id": 6, "description": "Application Context Name", "is_string": 1},
    "presentation_context": {"id": 7, "description": "Presentation Context"},
    "max_pdu_length": {"id": 8, "description": "Maximum PDU Length"},
    "implementation_class_uid": {"id": 9, "description": "Implementation Class UID", "is_string": 1},
    "pdv_length": {"id": 10, "description": "PDV Length"},
    "pdv_context": {"id": 11, "description": "PDV Context"},
    "pdv_flags": {"id": 12, "description": "PDV Flags"},
    "command_group_length": {"id": 13, "description": "Command Group Length"},
    "command_field": {"id": 14, "description": "Command Field"},
    # Meta-attributes below - not suitable for direct fuzzing
    "p_hdr": {"id": 4096, "description": "Packet Header", "note": "This is a meta-attribute and may not be suitable for direct fuzzing"},
    "p_data": {"id": 4097, "description": "Packet Data", "note": "This is a meta-attribute and may not be suitable for direct fuzzing"},
    "p_payload": {"id": 4098, "description": "Packet Payload", "note": "This is a meta-attribute and may not be suitable for direct fuzzing"},
    "packet_count": {"id": 4099, "description": "Packet Count", "note": "This is a meta-attribute and may not be suitable for direct fuzzing"},
    "data_count": {"id": 4100, "description": "Data Count", "note": "This is a meta-attribute and may not be suitable for direct fuzzing"},
    "payload_count": {"id": 4101, "description": "Payload Count", "note": "This is a meta-attribute and may not be suitable for direct fuzzing"},
    "first_packet_time": {"id": 4102, "description": "First Packet Time", "note": "This is a meta-attribute and may not be suitable for direct fuzzing"},
    "last_packet_time": {"id": 4103, "description": "Last Packet Time", "note": "This is a meta-attribute and may not be suitable for direct fuzzing"},
    "p_data_len": {"id": 4104, "description": "Packet Data Length", "note": "This is a meta-attribute and may not be suitable for direct fuzzing"},
    "stats": {"id": 4105, "description": "Statistics", "note": "This is a meta-attribute and may not be suitable for direct fuzzing"}
}

def setup_openai_api():
    """Setup the OpenAI API with the key from environment variable"""
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("Error: OPENAI_API_KEY environment variable not set.")
        print("Please set it with: export OPENAI_API_KEY='your-api-key'")
        sys.exit(1)

    openai.api_key = api_key
    return openai

def generate_rule_with_openai(prompt: str, model: str = "gpt-4") -> str:
    """Generate a DICOM rule based on the provided prompt using OpenAI API"""
    try:
        client = openai.OpenAI()

        # Prepare a list of valid attribute names for reference
        valid_attributes = ", ".join([f"'{attr}' (ID: {data['id']})" for attr, data in DICOM_ATTRIBUTES.items()
                                     if not ("note" in data and "meta-attribute" in data["note"])])

        system_prompt = f"""
        You are an expert in DICOM protocol testing and network fuzzing. Your task is to generate XML rules
        for testing DICOM attributes with valid or invalid values.

        Below is an example rule structure that modifies the PDU length:

        {EXAMPLE_RULE}

        Please generate a similar rule based on the user's request. The rule should:
        1. Include proper embedded C function with meaningful comments
        2. Set appropriate property_id, description, and if_satisfied attributes
        3. Define correct boolean_expression based on the attribute being tested
        4. Use replace_dicom_attribute() with protocol ID 701 and the correct attribute ID
        5. Properly set is_string to 1 for string values and 0 for numeric values

        IMPORTANT: You can ONLY use the following DICOM attributes:
        {valid_attributes}

        If the user requests an attribute that is not in this list, respond with:
        "The requested attribute is not supported in the current DICOM implementation. Please choose from the list of supported attributes: {valid_attributes}"

        Return ONLY the XML rule without any additional explanation if the attribute is supported,
        or ONLY the error message if it's not supported.
        """

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]

        response = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0.2,  # Lower temperature for more consistent outputs
            max_tokens=1000
        )

        generated_rule = response.choices[0].message.content.strip()

        # Check if the response contains the error message about unsupported attributes
        if "not supported in the current DICOM implementation" in generated_rule:
            return generated_rule  # Return the error message as is

        # Otherwise, clean up the response - extract just the XML
        if "```xml" in generated_rule:
            generated_rule = re.search(r"```xml\s*(.*?)\s*```", generated_rule, re.DOTALL).group(1)
        elif "```" in generated_rule:
            generated_rule = re.search(r"```\s*(.*?)\s*```", generated_rule, re.DOTALL).group(1)

        # Get a unique property ID
        unique_property_id = suggest_property_id()

        # Replace property_id in the generated rule with our unique ID
        generated_rule = re.sub(
            r'property_id="(\d+)"',
            f'property_id="{unique_property_id}"',
            generated_rule
        )

        # Add a comment about the property ID being automatically assigned
        if "<!-- Property" in generated_rule:
            # Replace existing Property comment
            generated_rule = re.sub(
                r'<!-- Property \d+:',
                f'<!-- Property {unique_property_id}:',
                generated_rule
            )
        else:
            # Add a comment at the beginning if not present
            first_line_end = generated_rule.find('\n')
            if first_line_end != -1:
                comment = f"<!-- Property {unique_property_id}: Auto-assigned unique ID -->\n"
                generated_rule = generated_rule[:first_line_end+1] + comment + generated_rule[first_line_end+1:]

        return generated_rule

    except Exception as e:
        print(f"Error generating rule: {e}")
        return None

def suggest_property_id() -> int:
    """Find the highest existing property ID in the rules directory and suggest the next available ID"""
    try:
        # Start from a reasonable default
        max_id = 31

        # Check if rules directory exists
        if os.path.exists("rules"):
            # Get all XML files in the rules directory
            xml_files = [f for f in os.listdir("rules") if f.endswith('.xml')]

            # Extract property_ids from all rule files
            for file in xml_files:
                try:
                    with open(os.path.join("rules", file), 'r') as f:
                        content = f.read()
                        # Find property_id="X" in the XML
                        matches = re.findall(r'property_id="(\d+)"', content)
                        if matches:
                            for match in matches:
                                try:
                                    prop_id = int(match)
                                    if prop_id > max_id:
                                        max_id = prop_id
                                except ValueError:
                                    # Not a valid integer, skip
                                    pass
                except Exception as e:
                    # If we can't read a file, just continue
                    print(f"Warning: Could not read {file}: {e}")
                    continue

        # Return the next available ID
        return max_id + 1
    except Exception as e:
        print(f"Warning: Error finding next property ID: {e}")
        # Default to a safe starting number if we can't determine existing IDs
        return 50

def save_rule_to_file(rule_content: str, filename: Optional[str] = None) -> str:
    """Save the generated rule to a file"""
    if not filename:
        # Extract description for filename
        match = re.search(r'description="([^"]+)"', rule_content)
        if match:
            description = match.group(1)
            # Create a safe filename from the description
            safe_name = re.sub(r'[^\w\s-]', '', description.lower())
            safe_name = re.sub(r'[\s-]+', '_', safe_name)
            filename = f"dicom_rule_{safe_name}.xml"
        else:
            # Fallback filename
            filename = f"dicom_rule_{suggest_property_id()}.xml"

    # Make sure we have the rules directory
    os.makedirs("rules", exist_ok=True)

    # If filename already starts with 'rules/', don't add it again
    if filename.startswith('rules/'):
        filepath = filename
    else:
        filepath = os.path.join("rules", filename)

    with open(filepath, 'w') as f:
        f.write(rule_content)

    return filepath

def main():
    parser = argparse.ArgumentParser(description="Generate DICOM testing rules using OpenAI")
    parser.add_argument("--model", default="gpt-4", help="OpenAI model to use (default: gpt-4)")
    parser.add_argument("--save", action="store_true", help="Save the rule to a file")
    parser.add_argument("--output", help="Output filename (optional)")
    parser.add_argument("prompt", nargs="?", help="Natural language description of the rule to generate")

    args = parser.parse_args()

    # Setup OpenAI API
    setup_openai_api()

    # Get prompt from command line or interactively
    prompt = args.prompt
    if not prompt:
        print("Enter your prompt (what DICOM attribute rule would you like to generate?)")
        print("Example: 'Give me a rule that modifies PDU length to an invalid value'")
        prompt = input("> ")

    print(f"\nGenerating rule for: '{prompt}'")
    rule = generate_rule_with_openai(prompt, args.model)

    if rule:
        # Extract the property_id assigned to the rule
        property_id_match = re.search(r'property_id="(\d+)"', rule)
        property_id = property_id_match.group(1) if property_id_match else "unknown"

        print(f"\nGenerated Rule (Property ID: {property_id}):")
        print("-" * 80)
        print(rule)
        print("-" * 80)

        if args.save:
            filepath = save_rule_to_file(rule, args.output)
            print(f"\nRule saved to: {filepath}")
            print(f"Property ID: {property_id} (automatically assigned to avoid conflicts)")
        else:
            print("\nRule generated successfully but not saved.")
            print("Use -s option to save the rule to a file for later use.")
    else:
        print("Failed to generate a rule.")

if __name__ == "__main__":
    main()