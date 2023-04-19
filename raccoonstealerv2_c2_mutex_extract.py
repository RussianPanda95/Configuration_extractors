# Tested on the latest unpacked/unobfuscated builds using the XOR instead of RC4

import re
import struct
import pefile
import argparse
import binascii

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="path of the binary file")
args = parser.parse_args()
pe = pefile.PE(args.file)

pe.relocate_image(0)

def xor_decrypt(data, key):
    out = []
    for i in range(len(data)):
        out.append(data[i] ^ key[i % len(key)])
    return out

rdata_start = None
rdata_end = None

for s in pe.sections:
    if s.Name.startswith(b'.rdata'):
        rdata_start = s.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
        rdata_end = rdata_start + s.Misc_VirtualSize

assert rdata_start is not None

text_data = None

for s in pe.sections:
    if s.Name.startswith(b'.text'):
        text_data = s.get_data()

assert text_data is not None

pattern = rb'\x6A(.)\xBA(....)\xB9(....)\xE8(....)'
pattern2 = rb'\x68(....).\x68\x01\x00\x1f\x00|\x68(....)..\x68\x01\x00\x1f\x00'

enc_str_strip = None
key = None
mutex = None

enc_strings = []
for m in re.finditer(pattern, text_data):
    str_len = struct.unpack('B', m.group(1))[0]
    str = struct.unpack('<I', m.group(3))[0]
    enc_str = struct.unpack('<I', m.group(2))[0]
    
    # Retrieving the encoded string
    if rdata_start <= enc_str <= rdata_end:
        enc_str = pe.get_data(enc_str - pe.OPTIONAL_HEADER.ImageBase, str_len)
        if len(enc_str) >= 32:
            enc_str_strip = enc_str[:enc_str.index(b'\x00')]
            print(f"Encoded string: {enc_str_strip}")

    # Retrieving the XOR key
    if rdata_start <= str <= rdata_end and str_len == 0x40:
        key = pe.get_data(str - pe.OPTIONAL_HEADER.ImageBase, str_len)
        break

decrypt_me = xor_decrypt(enc_str_strip, key)
decr_str = ''.join(map(chr, decrypt_me))

# Find last index of "/"
slash_strip = decr_str.rfind("/")
if slash_strip != -1:
    # Keep everything before the last "/"
    decr_str = decr_str[:slash_strip+1]

print(f"C2: {decr_str}")
key_hex = binascii.hexlify(key).decode('utf-8')
print(f"XOR Key: {key_hex[:46]}")

# Retrieving the Mutex/User-Agent string
for m in re.finditer(pattern2, text_data):
    if m.group(1):
        enc_str = struct.unpack('<I', m.group(1))[0]
    else:
        enc_str = struct.unpack('<I', m.group(2))[0]
    
    if rdata_start <= enc_str <= rdata_end:
        enc_str = pe.get_data(enc_str - pe.OPTIONAL_HEADER.ImageBase)
        mutex = enc_str[:28].decode('utf-8')

print(f"Mutex/User-Agent: {mutex}")
