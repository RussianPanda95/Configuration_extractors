# Author: RussianPanda
# Tested on samples:
#41a037f09bf41b5cb1ca453289e6ca961d61cd96eeefb1b5bbf153612396d919
#856a3df5b1930c1fcd5fdce56624f6f26a7e829ea331a182b4a28fd2707436f1
#b2a3112be417feb4f7c3b3f0385bdaee9213bf9cdc82136c05ebebb835c19a65

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
