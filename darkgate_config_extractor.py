# author: RussianPanda
# reference: https://0xtoxin.github.io/threat%20breakdown/DarkGate-Camapign-Analysis/
# tested on samples:
# e01cf9500da5d233d3f6e64f53933e9a2992c79273b73651a1ecbc6e9417bfeb
# c0ff92772cdf520a5b9791923bb246cb310be639e452ecbafcf6c3a57d0a5e31

import pefile
import re
import sys

def has_symbols(s):
    return any(char for char in s if not char.isalnum() and char not in [' ', '\t', '\n', '\r'])

def find_base64_pattern_in_pe(file_path):
    base64_pattern_64 = re.compile(b"[A-Za-z0-9+/=]{64}")
    base64_pattern_any = re.compile(b"[A-Za-z0-9+/=]+")

    pe = pefile.PE(file_path)
    data = pe.get_memory_mapped_image()
    all_encrypted_strings = []

    base64_64_matches = [match.group(0).decode(errors='replace') for match in base64_pattern_64.finditer(data)]

    # Assign the second and third matches as the non-standard table values
    if len(base64_64_matches) >= 3:
        custom_base64_str = base64_64_matches[1]
        custom_base64_str_two = base64_64_matches[2]

    for match in base64_pattern_any.finditer(data):
        matched_bytes = match.group(0).decode(errors='replace')
        if len(matched_bytes) >= 20:
            all_encrypted_strings.append(matched_bytes)

    for matched_bytes in base64_64_matches:
        all_encrypted_strings.append(matched_bytes)

    decoded_results = {}
    
    for s in all_encrypted_strings:
        decoded_string = decode_custom_base64(s, custom_base64_str, custom_base64_str_two)
        if decoded_string and has_symbols(decoded_string):
            decoded_string_alt = decode_custom_base64(s, custom_base64_str, custom_base64_str_two, use_custom_base64_str_two=True)
            if decoded_string_alt:
                decoded_results[s] = decoded_string_alt

    # Filter values that contain 'http://' or 'https://'
    http_results = {k: v for k, v in decoded_results.items() if 'http://' in v or 'https://' in v}
    for url in http_results.values():
        cleaned_url = url.replace("|", "")
        print(f"C2: {cleaned_url}\n")

    # Filter the first value that contains '0='
    config_match = next((v for v in decoded_results.values() if '0=' in v), None)
    if config_match:
        print(f"Configuration:\n{config_match}")

def decode_custom_base64(encoded_str, custom_base64_str, custom_base64_str_two, use_custom_base64_str_two=False):
    custom_base64_str_to_use = custom_base64_str_two if use_custom_base64_str_two else custom_base64_str
    return _decode_custom_base64(encoded_str, custom_base64_str_to_use)

def _decode_custom_base64(encoded_str, custom_base64_str):
    index_map = {char: i for i, char in enumerate(custom_base64_str)}
    
    def decode_block(block):
        index = [index_map[char] for char in block]
        while len(index) < 4:
            index.append(64)
        
        byte1 = (index[0] << 2) | (index[1] >> 4)
        byte2 = ((index[1] & 0x0F) << 4) | (index[2] >> 2)
        byte3 = ((index[2] & 0x03) << 6) | index[3]
        
        bytes_decoded = bytearray()
        bytes_decoded.append(byte1)
        if index[2] != 64:
            bytes_decoded.append(byte2)
        if index[3] != 64:
            bytes_decoded.append(byte3)
        return bytes_decoded
    
    try:
        decoded_bytes = bytearray()
        for i in range(0, len(encoded_str), 4):
            decoded_bytes += decode_block(encoded_str[i:i+4])
        return decoded_bytes.decode('utf-8', 'ignore')
    except Exception:
        return None

if __name__ == "__main__": 
    if len(sys.argv) != 2:
        print("Usage: python darkgate_config_extractor.py <path_to_file>")
        sys.exit(1) 

    file_path = sys.argv[1]
    find_base64_pattern_in_pe(file_path)