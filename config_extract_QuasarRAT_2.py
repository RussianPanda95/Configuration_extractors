# reference: https://research.openanalysis.net/quasar/chaos/rat/ransomware/2023/04/13/quasar-chaos.html
# using different key size, 32 bytes
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


data = dotnet_file.get_user_stream_strings()

base64_pattern = r"^(?!.*//)(?=.{20,})(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"

matches = []

for value in data:
    if re.search(base64_pattern, value):
        matches.append(value)

key_enc = matches[6]
key_enc = bytes(key_enc, 'utf-8')
key = pbkdf2_hmac("sha1", key_enc, salt, 50000, 32)
b64_values = ['Version','Hosts','Subdirectory', 'InstallName', 'Mutex', 'StartupKey', 'TAG','LOGDIRECTORYNAME']
value_decode_list = []
for value in matches:
    if re.search(base64_pattern, value):
        value_decode = b64decode(value)
        value_decode_list.append(value_decode)
iv = value_decode_list[0][32:48]

encryption_key = matches[8]
key_s = matches[6]
authkey = matches[3]

non_printable_ascii = re.compile('[^\x20-\x7E]')
value_strings = []
for value_decode in value_decode_list:
    try:
        value_decrypt = decrypt_AES(value_decode, key, iv)
        value_strip = value_decrypt[48:]
        value_strip = value_strip.decode()
        value_strip = non_printable_ascii.sub('', value_strip)
        value_strip = value_strip.replace('\n', '')
        value_strings.append(value_strip)
    except:
        pass

print("Version: " + value_strings[0])
print("Hosts: " + value_strings[1])
print("Subdirectory: " + value_strings[2])
print("InstallName: " + value_strings[3])
print("Mutex: " + value_strings[4])
print("StartupKey: " + value_strings[5])
print("Tag: " + value_strings[6])
print("EncryptionKey: " + key_s)
print("LogDirectoryName: " + value_strings[7])
print("ServerSignature: " + value_strings[8])
print("ServerCertificateStr: " + value_strings[9])

