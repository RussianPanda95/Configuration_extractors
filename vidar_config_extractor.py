# Author: RussianPanda 
# Tested on samples (samples can be found on https://www.unpac.me/): 
# 37c74886ce85682039bced4a6423e233aebd962921d9a76008d19ff75483a52c
# 6956fb2dd65d6627c23b680d4149983017bcb8e8b8fc1d30a5210998ca8cf801
# 3a7512884d5e269a6c9d74a0af38c0d4d4b95bdbe5c7cc8d8608e84a725d2134
# bd6370870671ccc61bb9a7ae5d31abc446e893dce15eeaff13deeb64f9317926
# ed28af0855aa6e00776f3633c15663e4a930f54ac399b48369f485e31250849b
# b30bdc75d85cac464fcc59df6a1db4c7ca19c93c2b42db961b41fd814c230d80
# 505e21494deb4e828da8bdfa386fa59a2599f89dc87276f25bd6d923aed13f83
# 279fff770c6678a1839799bd83aa9ace0c78380b9f93bd4b4a689c245382b4e6
# eba331ce626b9c6ca338c439b608d5234bfd0d0d5408de9e8b64e131435e4216

import re
import struct
import pefile
import argparse
import requests


parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="path of the binary file")
args = parser.parse_args()
pe = pefile.PE(args.file)

# Look for the C2 in the ".rdata" section
c2 = []
for s in pe.sections:
    if s.Name.startswith(b'.rdata'):
        rdata_start = s.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
        rdata_end = rdata_start + s.Misc_VirtualSize
        rdata_data = s.get_data()

for m in re.finditer(rb'(https?://[\d\w\.:/?#&+=_-]+)', rdata_data):
    matches = m.group().decode().split('\0')[0]
    if len(matches) > 8:
        c2.append(matches)

print(f"C2: {', '.join(c2)}")

# Retrieving C2 within the dead drops
for url in c2:
    try:
        response = requests.get(url, timeout=3)
    except Timeout:
        print(f"Timed out while connecting to {url}")
        continue

    ip_pattern = r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[^\|]*"
    ip_addresses = set(re.findall(ip_pattern, response.content.decode()))

    if len(ip_addresses) > 0:
        for ip in ip_addresses:
            print(f"C2: {ip}")
    else:
        print(f"Did not find any C2 in {url}.")

for s in pe.sections:
    if s.Name.startswith(b'.rdata'):
        rdata_start = s.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
        rdata_end = rdata_start + s.Misc_VirtualSize

try:
    rdata_data = None
    for s in pe.sections:
        if s.Name.startswith(b'.rdata'):
            rdata_start = s.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
            rdata_end = rdata_start + s.Misc_VirtualSize
            rdata_data = s.get_data()
            
    text_data = None
    for s in pe.sections:
        if s.Name.startswith(b'.text'):
            text_data = s.get_data()

    # Find version based on the opcodes
    pattern = rb'\x68(....)\x89\x45\xfc\x88\x06\xe8(....)\x83\xc4\x04|\x68(....)\x8b\xce\x89\x45\xfc\x88\x06'

    results = []
    for m in re.finditer(pattern, text_data):
        if m.group(1):
            enc_str = struct.unpack('<I', m.group(1))[0]
        elif m.group(2):
            enc_str = struct.unpack('<I', m.group(2))[0]
        else:
            enc_str = struct.unpack('<I', m.group(3))[0]
        if rdata_start <= enc_str <= rdata_end:
            enc_str = pe.get_string_at_rva(enc_str - pe.OPTIONAL_HEADER.ImageBase, 50)
            results.append(enc_str)

    version = None
    for result in results:
        if '.' in result and version is None:
            version = result
    print(f"Version: {version}")
 
# Look for the version in ".rdata"
except:
    version = []
    for m in re.finditer(rb'\b\d+\.\d+\b', rdata_data):
        version.append(m.group().replace(b'\x00', b''))
    print(f"Version: {(version[2].decode())}")
