import clr
import os
import re
import base64

DNLIB_PATH = 'path_to_dnlib\\dnlib.dll'
if not os.path.exists(DNLIB_PATH):
    raise FileNotFoundError(DNLIB_PATH)
clr.AddReference(DNLIB_PATH)

import dnlib
from dnlib.DotNet import *
from dnlib.DotNet.Emit import OpCodes

TARGET_PATH = 'path_to_binary'
module = dnlib.DotNet.ModuleDefMD.Load(TARGET_PATH)

def xor_data(data, key):
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def extract_strings_from_dotnet(target_path):
    module = ModuleDefMD.Load(target_path)
    hardcoded_strings = []
    for t in module.Types:
        for m in t.Methods:
            if m.HasBody:
                for instr in m.Body.Instructions:
                    if instr.OpCode == OpCodes.Ldstr:
                        hardcoded_strings.append(instr.Operand)
    return hardcoded_strings

extracted_strings = extract_strings_from_dotnet(TARGET_PATH)

b64 = r'^[A-Za-z0-9+/]+={0,2}$'
b64_strings = []
last_b64_index = -1

for i, string in enumerate(extracted_strings):
    if re.match(b64, string) and len(string) % 4 == 0 and len(string) > 20:
        b64_strings.append(string)
        last_b64_index = i

xor_key_match = None
if last_b64_index != -1 and last_b64_index + 2 < len(extracted_strings):
    xor_key_match = extracted_strings[last_b64_index + 2]

for i, string in enumerate(b64_strings):
    if i == 0:
        print("Authentication token:", string)
    else:
        break

xor_key = None

if last_b64_index is not None and last_b64_index + 1 < len(extracted_strings):
    potential_key = extracted_strings[last_b64_index + 1]
    if potential_key:
        xor_key = potential_key.encode()
    else:
        xor_key = xor_key_match.encode() if xor_key_match else None

if xor_key:
    for string in b64_strings[1:]:
        dec_Data = base64.b64decode(string)
        xor_result = xor_data(dec_Data, xor_key)
        try:
            final_result = base64.b64decode(xor_result)
            string_result = final_result.decode('utf-8')
            print("Decrypted String:", string_result)

        except Exception:
            pass

if len(b64_strings) < 3:
    dec_data_another = None
    xor_key_another = None

    if last_b64_index != -1 and last_b64_index + 1 < len(extracted_strings):
        dec_data_another = extracted_strings[last_b64_index + 1]

    if last_b64_index != -1 and last_b64_index + 2 < len(extracted_strings):
        xor_key_another = extracted_strings[last_b64_index + 3]

    if xor_key_another:
        xor_key = xor_key_another.encode()

        if dec_data_another:
            try:
                dec_Data = base64.b64decode(dec_data_another)
                xor_result = xor_data(dec_Data, xor_key)
                final_result = base64.b64decode(xor_result)
                string_result = final_result.decode('utf-8')
                print("Decrypted String:", string_result)
            except Exception as e:
                print(f"Error in decryption: {e}")
        for string in b64_strings:
            try:
                dec_Data = base64.b64decode(string)
                xor_result = xor_data(dec_Data, xor_key)
                final_result = base64.b64decode(xor_result)
                string_result = final_result.decode('utf-8')
                print("Decrypted String:", string_result)
            except Exception as e:
                continue
