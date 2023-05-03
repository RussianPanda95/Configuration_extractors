import re
import struct
import pefile
import argparse

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
            enc_str = pe.get_data(enc_str - pe.OPTIONAL_HEADER.ImageBase, 50)
            # Splits the strings at the null byte and takes the first part
            string = enc_str.decode().split('\0')[0]
            results.append(string)

    version = None
    c2 = []
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
