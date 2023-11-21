import clr
import re
import base64

DNLIB_PATH = 'path_to_dnlib\\dnlib.dll'
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
last_b64_index = None

for i, string in enumerate(extracted_strings):
    if re.match(b64, string) and len(string) % 4 == 0 and len(string) > 20:
        b64_strings.append(string)
        last_b64_index = i

for i, string in enumerate(b64_strings):
    if i == 0:
        print("Authentication token:", string)
    else:
        break

xor_key = None

if last_b64_index is not None and last_b64_index + 1 < len(extracted_strings):
    print("Key:", extracted_strings[last_b64_index + 1])
    xor_key = extracted_strings[last_b64_index + 1].encode()


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