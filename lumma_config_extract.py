import re
import base64
import argparse


def extract_b64(file_path, min_length=60, max_length=100):
    try:
        with open(file_path, 'rb') as file:
            binary_data = file.read()
    except FileNotFoundError:
        print("File not found. Please check the path and try again.")
        return []

    try:
        data = binary_data.decode('utf-8')
    except UnicodeDecodeError:
        data = binary_data.decode('latin1')

    pattern = r'(?:(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)'
    matches = re.findall(pattern, data)

    filtered_matches = [match for match in matches if min_length <= len(match) <= max_length]

    for match in filtered_matches:
        binary_match = match.encode('utf-8')

    return filtered_matches

def find_id_pattern(file_path):
    id_pattern = b'\x66\x69\x6E\x64\x69\x6E\x67\x20\x63\x65\x6E\x74\x72\x61\x6C\x20\x64\x69\x72\x65\x63\x74\x6F\x72\x79\x00'
    try:
        with open(file_path, 'rb') as file:
            binary_data = file.read()
    except FileNotFoundError:
        print("File not found. Please check the path and try again.")
        return None

    match = re.search(id_pattern, binary_data)
    if match:
        start_index = match.end()
        build_id = bytearray()
        while start_index < len(binary_data) and binary_data[start_index] != 0x00:
            build_id.append(binary_data[start_index])
            start_index += 1

        build_id_str = build_id.decode('utf-8', errors='ignore').strip()

        if '--' in build_id_str:
            parts = build_id_str.split('--', 1)
            if not parts[1].strip(): 
                return f"User ID: {build_id_str.strip()}"
            else:
                return f"Build ID: {build_id_str.strip()}"
        else:
            return f"User ID: {build_id_str.strip()}"
    return None


def xor_decrypt(encoded_str):
    try:
        dec_data = base64.b64decode(encoded_str)

        key = dec_data[:32]
        data = dec_data[32:]

        decrypted = bytearray()
        for i in range(len(data)):
            decrypted.append(data[i] ^ key[i % len(key)])

        decrypted_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in decrypted)

        domain_match = re.search(r'([a-zA-Z0-9-]+\.[a-zA-Z]{2,})', decrypted_str)
        return domain_match.group(1) if domain_match else None
    except Exception as e:
        print(f"Error decrypting data: {e}")
        return None

def static_analysis(file_path):
    print("Starting static analysis...")

    # Extract and decrypt C2 domains
    base64_strs = extract_b64(file_path)
    domains = []

    for string in base64_strs:
        result = xor_decrypt(string)
        if result:
            domains.append(result)

    unique_domains = list(set(domains))
    print("\nC2 Domains:")
    for domain in unique_domains:
        print(f"  - {domain.strip()}")
    id_value = find_id_pattern(file_path)
    if id_value:
        print(f"\n{id_value}")
    else:
        print("\nBuild ID not found.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Lumma Config Extractor")
    parser.add_argument("file_path", help="The path to the file to analyze")
    args = parser.parse_args()

    static_analysis(args.file_path)
