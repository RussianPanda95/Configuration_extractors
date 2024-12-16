import argparse
import struct

import pefile

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="path of the binary file")
    args = parser.parse_args()
    pe = pefile.PE(args.file)

    bytes = bytearray()

    d_section = pe.sections[6]
    d_section = d_section.get_data()
    data = d_section[0:100]
    for i in range(32):
        bytes.append(data[i + 64] ^ data[i])
    campaign_id = struct.unpack("<I", bytes[:4])[0]
    c2 = bytes[4:].split(b"\x00")[0].decode()

    print(f"C2: {c2}\nCampaign ID: {campaign_id}")
