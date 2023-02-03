# reference: https://www.0ffset.net/reverse-engineering/challenge-1-gozi-string-crypto/

import pefile 
import struct

pe = pefile.pe('filename')

encrypted_data = None
for section in pe.sections:
    if b".bss" in section.Name:
        encrypted_data = section.get_data()
        #print(f"encrypted data:{enctypted_data}")

def decryptBSS_Section(stringData, key):
    index = 0
    decoded_data = b""
    for i in range(0, len(stringData), 4):
        encrypted_DWORD = struct.unpack("I", stringData[i:i+4])[0]
        if encrypted_DWORD:
            decoded_data += struct.pack("I", (index - key + encrypted_DWORD) & 0xFFFFFFFF)
            index = encrypted_DWORD
    return decoded_data

key = 0x81b8e7da
key += 19

decryptedBytes = decryptBSS_Section(encrypted_data, key)
