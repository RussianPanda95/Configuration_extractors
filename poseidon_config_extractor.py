# Author: RussianPanda

import re
import sys
import json
import hashlib

printed_configs = set()

def custom_base64_decode(encrypted_data, custom_alphabet):
    char_map = {char: index for index, char in enumerate(custom_alphabet)}
    decoded_bits = 0
    bit_count = 0
    decoded_bytes = []

    for char in encrypted_data:
        if char in char_map:
            decoded_bits = (decoded_bits << 6) | char_map[char]
            bit_count += 6

            while bit_count >= 8:
                bit_count -= 8
                decoded_bytes.append((decoded_bits >> bit_count) & 0xFF)

    return bytes(decoded_bytes)

def transform_decoded_data(decoded_bytes, output_length):
    output_length = min(output_length, len(decoded_bytes))
    transformed_bytes = [(256 + decoded_bytes[k] - 3) % 256 for k in range(output_length)]
    return bytes(transformed_bytes)

def extract_data_to_json(readable_output):
    data = {
        "uuid": None,
        "user": None,
        "buildid": None,
        "C2": None,
        "staging_folder": None
    }

    uuid_match = re.search(r'uuid:\s*([a-f0-9\-]+)', readable_output, re.IGNORECASE)
    if uuid_match:
        data["uuid"] = uuid_match.group(1)

    user_match = re.search(r'user:\s*([\w-]+)', readable_output, re.IGNORECASE)
    if user_match:
        data["user"] = user_match.group(1)

    buildid_match = re.search(r'buildid:\s*([\w-]+)', readable_output, re.IGNORECASE)
    if buildid_match:
        data["buildid"] = buildid_match.group(1)

    c2_match = re.search(r'http[s]?://\S+', readable_output)
    if c2_match:
        data["C2"] = c2_match.group(0)

    staging_folder_match = re.search(r'--data-binary\s+@\S+', readable_output)
    if staging_folder_match:
        data["staging_folder"] = staging_folder_match.group(0).split('@')[1]

    return data

def find_valid_start(binary_data, start_pos):
    while start_pos < len(binary_data):
        char = binary_data[start_pos:start_pos + 1].decode('ascii', errors='ignore')
        if char.isascii() and char.isalpha():
            return start_pos
        start_pos += 1
    return None

def convert_hex_to_ascii(hex_data):
    cleaned_hex_data = re.sub(r'[^0-9a-fA-F]', '', hex_data.decode('utf-8', errors='ignore') if isinstance(hex_data, bytes) else hex_data)
    return ''.join([chr(int(cleaned_hex_data[i:i+2], 16)) for i in range(0, len(cleaned_hex_data), 2) if len(cleaned_hex_data[i:i+2]) == 2])

def convert_hex_to_readable_string(hex_data):
    try:
        cleaned_hex_string = re.sub(r'[^0-9a-fA-F]', '', hex_data)
        return bytes.fromhex(cleaned_hex_string).decode('ascii', errors='ignore')
    except (ValueError, UnicodeDecodeError):
        return hex_data.decode('ascii', errors='ignore')

def process_config_data(readable_output):
    config_data = extract_data_to_json(readable_output)
    if any(config_data.values()):
        json_output = json.dumps(config_data, indent=4)
        if json_output not in printed_configs:
            print("Config:", json_output)
            printed_configs.add(json_output)

if len(sys.argv) < 2:
    print("Usage: python poseidon_config_extractor.py <file_path>")
    sys.exit(1)

file_path = sys.argv[1]

with open(file_path, "rb") as binary_file:
    file_data = binary_file.read()
    sha256_hash = hashlib.sha256(file_data).hexdigest()
    print(f"SHA-256: {sha256_hash}")

custom_alphabet_pattern = rb'[A-Za-z0-9+/=]{64}'

match = re.search(custom_alphabet_pattern, file_data)

if match:
    custom_alphabet = match.group().decode('utf-8', errors='ignore')
    start_pos = match.start()

    initial_offsets = 0x87
    enc_data_start = start_pos + len(custom_alphabet) + initial_offsets
    valid_start = find_valid_start(file_data, enc_data_start)

    if valid_start is not None and valid_start < len(file_data):
        null_byte_pos = file_data.find(b'\x00', valid_start)
        enc_data = file_data[valid_start:null_byte_pos] if null_byte_pos != -1 else file_data[valid_start:]

        decoded_bytes = custom_base64_decode(enc_data.decode('utf-8', errors='ignore'), custom_alphabet)
        transformed_data = transform_decoded_data(decoded_bytes, 39294)
        readable_output = convert_hex_to_ascii(transformed_data)

        if "osascript" in readable_output:
            process_config_data(readable_output)

    # Trying to extract the hex string if no valid config has been found
    if not printed_configs:
        long_hex_pattern = rb'\x00{2,}[0-9a-fA-F]{430,}'
        long_hex_match = re.search(long_hex_pattern, file_data)
        if long_hex_match:
            long_hex_data = long_hex_match.group().lstrip(b'\x00')

            readable_output = convert_hex_to_readable_string(long_hex_data.decode('ascii'))
            process_config_data(readable_output)
else:
    print("No custom alphabet found.")
