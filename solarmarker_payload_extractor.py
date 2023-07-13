# Author: RussianPanda
# Tested on sample: 1160da03685be4abedafa4f03b02cdf3f3242bc1d6985187acf281f5c7e46168

import re
from dotnetfile import DotNetPE
from base64 import b64decode
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import argparse


parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="path of the binary file", required=True)
args = parser.parse_args()

dotnet_file_path = args.file
dotnet_file = DotNetPE(dotnet_file_path)

data = dotnet_file.get_user_stream_strings()

base64_pattern = r"^(?=.{20,})(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
base64_regex = re.compile(base64_pattern)

matches = []
for string in data:
    matches.extend([match.group() for match in base64_regex.finditer(string) if match])

matches_string = ''.join(matches)

try:
    decoded_bytes = b64decode(matches_string)
    decoded = decoded_bytes.decode('utf-8') 
except Exception as e:
    print(f"Error while decoding base64 string: {e}")
    decoded = ''

url_pattern = r"https://[\w\./-]*"
url_regex = re.compile(url_pattern)

url_matches = [match.group() for match in url_regex.finditer(decoded) if match]

url_str = '\n'.join(url_matches)
if len(url_matches) >= 2:
    server_url = url_matches[1]
    print("Payload serving URL found:", server_url)

if len(url_matches) >= 2:
    server_url = url_matches[1]

    try:
        response = requests.get(server_url)

        # If the request is successful, the status code == 200
        if response.status_code == 200:
            content = response.text 
    except requests.exceptions.RequestException as e:
        print(f"Request failed due to an exception: {e}")

content = response.text  

pattern = r"FromBase64String\('([^']*)="
regex = re.compile(pattern)

base64_payload = [match.group(1) + '=' for match in regex.finditer(content) if match]

key_pattern = r'\$A\.Key=@\(\[byte\](.*?)\);'
iv_pattern = r'\$A\.IV=@\(\[byte\](.*?)\);'

key_match = re.search(key_pattern, content)
iv_match = re.search(iv_pattern, content)

if key_match:
    key = key_match.group(1)
    key_bytes = bytes([int(x) for x in key.split(',')])
    print('Key: ', key_bytes)

if iv_match:
    iv = iv_match.group(1)
    iv_bytes = bytes([int(x) for x in iv.split(',')])
    print('IV: ', iv_bytes)

for i, b64_str in enumerate(base64_payload):
    try:
        decoded = b64decode(b64_str)

        cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv_bytes)
        decrypted_payload = unpad(cipher.decrypt(decoded), AES.block_size)

        # Write the second-stage payload to a file
        with open(f'second_stage_payload.bin', 'wb') as f:
            f.write(decrypted_payload)
        print("Success: 'second_stage_payload.bin' has been created")

    except Exception as e:
        print(f"Error while decrypting base64 string: {e}")
