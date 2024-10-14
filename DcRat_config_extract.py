# Author: RussianPanda

# Reference:
# https://research.openanalysis.net/dot%20net/static%20analysis/stormkitty/dnlib/python/research/2021/07/14/dot_net_static_analysis.html
# https://github.com/embee-research/Asyncrat-Venom-Dcrat-Config-Extractor/blob/main/asyncrat-config-extractor.py#L161

# Tested on: bac8861baa346f0ce06c87c33284d478

import base64
import hashlib
import hmac
import re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from dotnetfile import DotNetPE
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="path of the binary file", required=True)
args = parser.parse_args()


def is_base64(s):
    pattern = r'^[A-Za-z0-9+/]{20,}={0,2}$'
    return re.match(pattern, s) is not None

def decode_and_check_length(base64_string):
    try:
        decoded_bytes = base64.b64decode(base64_string, validate=True)
        return len(decoded_bytes) == 32
    except Exception:
        return False

def get_aes_key(key, salt, keysize):
    key = base64.b64decode(key)
    salt = salt.encode('ascii')
    return hashlib.pbkdf2_hmac("sha1", key, salt, 50000, keysize)

def get_IV(authkey, enc):
    data = base64.b64decode(enc)
    data = data[32:]  # Skip HMAC 
    iv = hmac.new(authkey, data, hashlib.sha256).digest()
    return iv[:16]  # First 16 bytes for IV

def aes_decrypt_and_extract_data(enc, key, iv, skip_bytes):
    enc = base64.b64decode(enc)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(enc) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return decrypted_data[skip_bytes:]

dotnet_file_path = args.file
dotnet_file = DotNetPE(dotnet_file_path)

us_stream_strings = dotnet_file.get_user_stream_strings()

key = None
for string in us_stream_strings:
    if is_base64(string) and decode_and_check_length(string):
        key = string
        break  

if key is None:
    print("No key found.")

skip_bytes = 48

salt = "DcRatByqwqdanchun" ## Salt value might be different

# Generate AES Keys from salt
key1 = get_aes_key(key, salt, 32)
key2 = get_aes_key(key, salt, 96)
key2 = key2[32:]

decrypted_strings = []

for string in us_stream_strings:
    if is_base64(string) and string != key:
        try:
            iv = get_IV(key2, string)
            decrypted_data = aes_decrypt_and_extract_data(string, key1, iv, skip_bytes)
            decrypted_strings.append(decrypted_data)
        except ValueError as e:
            if "not a multiple of the block length" in str(e):
                continue

try:
    Por_ts, Hos_ts, Ver_sion, In_stall, MTX, Certifi_cate, Server_signa_ture, Paste_bin, BS_OD, Group, Anti_Process, An_ti = decrypted_strings
except ValueError as e:
    print(f"Error assigning variables: {e}")


# Variables can be different

print(f"Ports: {Por_ts}")
print(f"Hos_ts: {Hos_ts}")
print(f"Ver_sion: {Ver_sion}")
print(f"In_stall: {In_stall}")
print(f"MTX: {MTX}")
print(f"Certifi_cate: {Certifi_cate}")
print(f"Server_signa_ture: {Server_signa_ture}")
print(f"Paste_bin: {Paste_bin}")
print(f"BS_OD: {BS_OD}")
print(f"Group: {Group}")
print(f"Anti_Process: {Anti_Process}")
print(f"An_ti: {An_ti}")