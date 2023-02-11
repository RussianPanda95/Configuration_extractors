from dotnetfile import DotNetPE
from Crypto.Cipher import AES
from backports.pbkdf2 import pbkdf2_hmac
from base64 import b64decode
import re
import argparse


parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="path of the binary file", required=True)
args = parser.parse_args()

def decrypt_AES(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext 

salt = b'\xbf\xeb\x1e\x56\xfb\xcd\x97\x3b\xb2\x19\x02\x24\x30\xa5\x78\x43\x00\x3d\x56\x44\xd2\x1e\x62\xb9\xd4\xf1\x80\xe7\xe6\xc3\x39\x41'
dotnet_file_path = args.file
dotnet_file = DotNetPE(dotnet_file_path)

data = dotnet_file.get_user_stream_strings()

''' 	// Token: 0x04000045 RID: 69
		private const int KeyLength = 32;

		// Token: 0x04000046 RID: 70
		private const int AuthKeyLength = 64;

		// Token: 0x04000047 RID: 71
		private const int IvLength = 16;

		// Token: 0x04000048 RID: 72
		private const int HmacSha256Length = 32; '''
        
b64dec = data[1:2][0]
b64dec = b64decode(b64dec)
key_enc = data[7:8][0]
key_dec = b64decode(key_enc).decode()
key = bytes(key_dec, 'utf-8')

dec_key = pbkdf2_hmac("sha1", key, salt, 50000, 32)
iv = b64dec[32:48]

# look for base64 pattern
base64_pattern = r"^(?=.{20,})(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"

b64_values = ['Ports','Hosts','Version','Install','Key','MTX','Certificate', 'ServerSignature', 'Anti', 'offlineKL', 'clipper','btc', 'eth','tron', 'Pastebin','BDOS', 'Group']
other_list = ["InstallFolder", "InstallFile", "Delay", "Hwid"]

value_strings = []
counter_list = []

counter = 0
for value in data:
    if re.search(base64_pattern, value):
        value_decode = b64decode(value)
        value_decrypt = decrypt_AES(value_decode, dec_key, iv)
        value_strip = value_decrypt[48:]
        value_strip = value_strip.decode()
        value_strip = re.sub(r'[^a-zA-Z0-9 _.,|]+', '', value_strip) 
        value_strings.append(value_strip)
    else:
        counter += 1
        if 2 <= counter <= 5:
            counter_list.append(value)
        elif counter > 5:
            break

for i in range(len(counter_list)):
    print(other_list[i] + ": " + counter_list[i])

# appending to the key item
value_strings[4] = data[7:8][0] 

for i in range(len(value_strings)):
    print(b64_values[i] + ": " + value_strings[i])
         

