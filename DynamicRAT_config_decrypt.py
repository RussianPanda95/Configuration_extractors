# Author: RussianPanda
# Tested on samples:
#41a037f09bf41b5cb1ca453289e6ca961d61cd96eeefb1b5bbf153612396d919
#856a3df5b1930c1fcd5fdce56624f6f26a7e829ea331a182b4a28fd2707436f1
#b2a3112be417feb4f7c3b3f0385bdaee9213bf9cdc82136c05ebebb835c19a65

import zipfile
import re
import hashlib
import binascii
from Crypto.Cipher import AES

file_path = input("Enter the file path: ")

jar_file_path = file_path  # Assuming the JAR file path is the same as the input file path
assets_file_path = "assets.dat"

class_file = 'dynamic/client/Main.class'
search_pattern = rb"assets\.dat.{8}([A-Za-z0-9!@#$%^&*()-_=+{}\[\]|:;'<>,./?]+)"

with zipfile.ZipFile(jar_file_path, 'r') as jar:
    try:
        # Extract the "Main.class" file contents as bytes
        file_bytes = jar.read(class_file)
    except KeyError:
        print(f"The file '{class_file}' does not exist in the JAR file.")
        exit(1)

    # Find the mention of "assets.dat" and extract the desired string
    match = re.search(search_pattern, file_bytes)
    if match:
        extracted_bytes = match.group(1)
        extracted_key = extracted_bytes.decode('utf-8')
        print(f"Extracted key: {extracted_key}")
    else:
        print("Key not found in the file.")

key = hashlib.md5(extracted_key.encode("utf-8")).digest()


with zipfile.ZipFile(jar_file_path, 'r') as jar:
    try:
        # Extract the "assets.dat" file contents as bytes
        encrypted_data_bytes = jar.read(assets_file_path)[4:]  # Skip the first four bytes
    except KeyError:
        print(f"The file '{assets_file_path}' does not exist in the JAR file.")
        exit(1)

encrypted_data = bytes(encrypted_data_bytes)

cipher = AES.new(key, AES.MODE_ECB)

decrypted_data = cipher.decrypt(encrypted_data)

print("Decrypted data:", decrypted_data)

