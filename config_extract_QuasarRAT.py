from dotnetfile import DotNetPE
from Crypto.Cipher import AES
from backports.pbkdf2 import pbkdf2_hmac
from base64 import b64decode
import re
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="path of the binary file", required=True)
args = parser.parse_args()
dotnet_file_path = args.file
dotnet_file = DotNetPE(dotnet_file_path)

def decrypt_AES(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext 

salt = b'\xbf\xeb\x1e\x56\xfb\xcd\x97\x3b\xb2\x19\x02\x24\x30\xa5\x78\x43\x00\x3d\x56\x44\xd2\x1e\x62\xb9\xd4\xf1\x80\xe7\xe6\xc3\x39\x41'

dotnet_file = DotNetPE(dotnet_file_path)

data = dotnet_file.get_user_stream_strings()

base64_pattern = r"^(?!.*//)(?=.{20,})(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"

matches = []

for value in data:
    if re.search(base64_pattern, value):
        matches.append(value)

key_enc = matches[8]
key_enc = bytes(key_enc, 'utf-8')
key = pbkdf2_hmac("sha1", key_enc, salt, 50000, 16)

b64_values = ['Version','Hosts','Subdirectory', 'InstallName', 'Mutex', 'StartupKey', 'TAG','LOGDIRECTORYNAME']
other_list = ['Key','EncryptionKey','Authkey']
value_decode_list = []
for value in matches:
    if re.search(base64_pattern, value):
        value_decode = b64decode(value)
        value_decode_list.append(value_decode)
iv = value_decode_list[0][32:48]

encryption_key = matches[8]
key_s = matches[2]
authkey = matches[3]

non_printable_ascii = re.compile('[^\x20-\x7E]')
value_strings = []
for value_decode in value_decode_list:
    try:
        value_decrypt = decrypt_AES(value_decode, key, iv)
        value_strip = value_decrypt[48:]
        value_strip = value_strip.decode()
        # Remove non-printable ASCII characters
        value_strip = non_printable_ascii.sub('', value_strip)
        # Replace "\n" with an empty string
        value_strip = value_strip.replace('\n', '')
        value_strings.append(value_strip)
    except:
        pass

del value_strings[2]

for i, value_string in enumerate(value_strings):
    b64_values[i] += ": " + value_string
b64_values_str = "\n".join(b64_values)

print(b64_values_str)

print("Key: " + key_s)
print("EncryptionKey: " + encryption_key)
print("Authkey: " + authkey)