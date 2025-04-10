# Author: RussianPanda
# Sample: 911981d657b02f2079375eecbd81f3d83e5fa2b8de73afad21783004cbcc512d
import re
import base64
import argparse
import string
import json

def rc4_ksa(key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def rc4_prga(S, data):
    i = 0
    j = 0
    result = bytearray()
    
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(byte ^ k)
    
    return bytes(result)

def rc4_decrypt(data, key):
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    if isinstance(data, str):
        try:
            # Try to convert from hex string
            data = bytes.fromhex(data)
        except:
            # If not hex, use as-is
            data = data.encode('utf-8')
    
    S = rc4_ksa(key)
    return rc4_prga(S, data)

def find_and_decrypt_strings(binary_data, rc4_key):

    printable_pattern = rb'(?:[\x20-\x7E]{4,})'
    
    base64_pattern = re.compile(b'[A-Za-z0-9+/=]{4,}')
    
    special_pattern = re.compile(rb'/[A-Za-z0-9+/]{4,}=*')
    
    potential_strings = []
    
    for match in re.finditer(printable_pattern, binary_data):
        potential_strings.append(match.group(0))
    
    for match in re.finditer(base64_pattern, binary_data):
        if match.group(0) not in potential_strings:
            potential_strings.append(match.group(0))
    
    for match in re.finditer(special_pattern, binary_data):
        if match.group(0) not in potential_strings:
            potential_strings.append(match.group(0))
    
    results = []
    for encrypted_bytes in potential_strings:
        try:
            encrypted = encrypted_bytes.decode('utf-8', errors='ignore')
            
            decrypted = rc4_decrypt(encrypted_bytes, rc4_key)
            
            try:
                decrypted_str = decrypted.decode('utf-8', errors='replace')
            except:
                decrypted_str = str(decrypted)
            
            base64_decrypted_str = None
            if re.match(r'^[A-Za-z0-9+/]*={0,2}$', encrypted) and len(encrypted) % 4 == 0:
                try:
                    decoded = base64.b64decode(encrypted_bytes)
                    base64_decrypted = rc4_decrypt(decoded, rc4_key)
                    
                    try:
                        base64_decrypted_str = base64_decrypted.decode('utf-8', errors='replace')
                    except:
                        base64_decrypted_str = str(base64_decrypted)
                except:
                    base64_decrypted_str = None
            
            if encrypted.startswith('/'):
                try:
                    clean_str = encrypted[1:]
                    padding_needed = len(clean_str) % 4
                    if padding_needed:
                        clean_str += '=' * (4 - padding_needed)
                    
                    decoded = base64.b64decode(clean_str)
                    special_decrypted = rc4_decrypt(decoded, rc4_key)
                    
                    try:
                        special_decrypted_str = special_decrypted.decode('utf-8', errors='replace')
                        if base64_decrypted_str is None:
                            base64_decrypted_str = special_decrypted_str
                    except:
                        pass
                except:
                    pass
            
            results.append({
                'encrypted': encrypted,
                'direct_decrypted': decrypted_str,
                'base64_decrypted': base64_decrypted_str
            })
        except Exception as e:
            continue
    
    return results

def is_valid_string(s, min_length=4):
    if len(s) < min_length:
        return False
    
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', s):
        return True
    
    if any(c.isalpha() for c in s):
        return True
    
    if s.isdigit() and len(s) >= 4:
        return True
    
    return False

def find_opcode(binary_data):

    opcode = bytes.fromhex("73 74 72 69 6E 67 20 74 6F 6F 20 6C 6F 6E 67")
    
    positions = []
    pos = binary_data.find(opcode)
    
    while pos != -1:
        positions.append(pos)
        pos = binary_data.find(opcode, pos + 1)
    
    if positions:
        build_id = None
        rc4_key = None
        
        for pos in positions:
            next_bytes = binary_data[pos + len(opcode):pos + len(opcode) + 120]
            
            
            current_str = ""
            for i, b in enumerate(next_bytes):
                if 32 <= b <= 126:
                    current_str += chr(b)
                elif current_str:
                    build_id = current_str
                    break
            
            string_count = 0
            current_str = ""
            for b in next_bytes:
                if 32 <= b <= 126:
                    current_str += chr(b)
                else:
                    if current_str:
                        string_count += 1
                        if string_count == 3:
                            rc4_key = current_str
                            break
                        current_str = ""
            
            if build_id and rc4_key:
                break
        
        return {
            "build_id": build_id,
            "rc4_key": rc4_key
        }
    else:
        return None

def find_c2(decrypted_strings):
    ip_pattern = re.compile(r'^\d+\.\d+\.\d+\.\d+$')
    path_pattern = re.compile(r'^/[a-zA-Z0-9._/-]+\.php$')
    
    ip_address = None
    path = None
    
    for s in decrypted_strings:
        if ip_pattern.match(s):
            ip_address = s
            break
    
    if ip_address:
        ip_index = decrypted_strings.index(ip_address)
        for i in range(ip_index + 1, min(ip_index + 5, len(decrypted_strings))):
            if i < len(decrypted_strings) and path_pattern.match(decrypted_strings[i]):
                path = decrypted_strings[i]
                break
    
    if ip_address and path:
        return f"{ip_address}{path}"
    elif ip_address:
        return ip_address
    else:
        return None

def main():
    parser = argparse.ArgumentParser(description='Find and decrypt strings in binary files')
    parser.add_argument('file', help='Binary file to analyze')
    parser.add_argument('--min-length', type=int, default=4, help='Minimum length for decrypted strings (default: 4)')
    args = parser.parse_args()
    
    try:
        with open(args.file, 'rb') as f:
            binary_data = f.read()
    except FileNotFoundError:
        print(f"Error: File '{args.file}' not found.")
        return
    
    detected_info = find_opcode(binary_data)
    
    rc4_key = detected_info["rc4_key"] if detected_info and detected_info["rc4_key"] else args.key
    
    results = find_and_decrypt_strings(binary_data, rc4_key)
    
    printable_chars = set(string.printable)
    
    unique_decrypted = []
    seen = set()
    
    for result in results:
        if 'base64_decrypted' in result and result['base64_decrypted']:
            decrypted = result['base64_decrypted']
            if (all(c in printable_chars for c in decrypted) and 
                is_valid_string(decrypted, args.min_length) and
                decrypted not in seen):
                seen.add(decrypted)
                unique_decrypted.append(decrypted)
        
        elif 'direct_decrypted' in result:
            decrypted = result['direct_decrypted']
            if (all(c in printable_chars for c in decrypted) and 
                is_valid_string(decrypted, args.min_length) and
                decrypted not in seen):
                seen.add(decrypted)
                unique_decrypted.append(decrypted)
    
    c2_url = find_c2(unique_decrypted)
    
    output_data = {
        "metadata": {
            "build_id": detected_info["build_id"] if detected_info else None,
            "rc4_key": rc4_key,
            "c2": c2_url
        },
        "decrypted_strings": unique_decrypted
    }
    
    print(json.dumps(output_data, indent=4))

if __name__ == "__main__":
    main()