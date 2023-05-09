# Author: RussianPanda
# Tested on samples (samples can be found on www.unpac.me):
# 8fc683128de2f77baddeff88b5fb427c70f9f099cd293032d780e3e06b6f947b
# fd37c98782453214bab6484f6045b796a5a3dc7ebba9a894f6783817eef6c9c7
# dd651c2ffe94faf59e3a3db2da56e05a1a12fcae7cd5f87881d1cb036be3ec2a

import pefile
import struct
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="path of the binary file")
args = parser.parse_args()
pe = pefile.PE(args.file)

for s in pe.sections:
    if s.SizeOfRawData > 256:
        data_start = s.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
        data_end = data_start + s.Misc_VirtualSize
        data = s.get_data()

bytes = bytearray()

for i in range(32):
    bytes.append(data[i] ^ data[i+64])

key = data[:32].hex()
campaign_id = struct.unpack("<I", bytes[:4])[0]
c2 = bytes[4:].split(b'\x00')[0].decode()
print(f"C2: {c2}")
print(f"Campaign ID: {campaign_id}")
print(f"Key: {key}")
