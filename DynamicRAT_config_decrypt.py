# Author: RussianPanda
# Tested on samples:
# a7eeab7e2e90d0373ebfb15243bff81a
# afdb44fb193de084ecccdf3a1402f4df
# df63d9e76da54614bf22613fca437b04

import hashlib
import binascii
from Crypto.Cipher import AES

file_path = input("Enter the file path: ")
password = input("Enter the password: ")

md5_hash = hashlib.md5(password.encode("utf-8")).digest()

key = binascii.hexlify(md5_hash).decode("utf-8")
key_bytes = [int(key[i:i+2], 16) for i in range(0, len(key), 2)]

with open(file_path, "rb") as file:
    file.seek(4)  # Skip the first four bytes
    encrypted_data_bytes = file.read()

key = bytes(key_bytes)
encrypted_data = bytes(encrypted_data_bytes)

cipher = AES.new(key, AES.MODE_ECB)

decrypted_data = cipher.decrypt(encrypted_data)

print("Decrypted data:", decrypted_data)
