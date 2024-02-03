# Author: RussianPanda
# Tested on sample: 63a2dcb487d0d875688f4e4d5251a93b

import argparse
import string

import pefile
from Crypto.Cipher import ARC4


def decrypt_rc4_data(data, key):
    cipher = ARC4.new(key)
    return cipher.decrypt(data)


def extract_all_rcdata(pe_file):
    pe = pefile.PE(pe_file)
    rcdata_values = []

    # Check if the PE file has a resource directory
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        # Traverse the resource directory
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if entry.id == pefile.RESOURCE_TYPE["RT_RCDATA"]:
                for resource in entry.directory.entries:
                    for entry_lang in resource.directory.entries:
                        data_rva = entry_lang.data.struct.OffsetToData
                        size = entry_lang.data.struct.Size
                        data = pe.get_memory_mapped_image()[data_rva : data_rva + size]
                        rcdata_values.append(data)

    return rcdata_values


parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="path of the binary file", required=True)
args = parser.parse_args()

rcdata_contents = extract_all_rcdata(args.file)

if rcdata_contents:
    for rcdata in rcdata_contents:
        if len(rcdata) > 1:
            key_length = rcdata[0]
            key = rcdata[1 : 1 + key_length]
            encrypted_data = rcdata[1 + key_length :]
            decrypted_data = decrypt_rc4_data(encrypted_data, key)
            decoded_data = decrypted_data.decode("utf-8", "replace")
            printable = set(string.printable)  #
            filtered_data = "".join(filter(lambda x: x in printable, decoded_data))
            print("Decrypted Config:", filtered_data)
else:
    print("No RCDATA found")
