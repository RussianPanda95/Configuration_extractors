#Author: RussianPanda
#Tested on samples:
# f7b02278a2310a2657dcca702188af461ce8450dc0c5bced802773ca8eab6f50
# c219beaecc91df9265574eea6e9d866c224549b7f41cdda7e85015f4ae99b7c7

import argparse
import clr

parser = argparse.ArgumentParser(description='Extract information from a target assembly file.')
parser.add_argument('-f', '--file', required=True, help='Path to the stealer file')
parser.add_argument('-d', '--dnlib', required=True, help='Path to the dnlib.dll')
args = parser.parse_args()

clr.AddReference(args.dnlib)

import dnlib
from dnlib.DotNet import *
from dnlib.DotNet.Emit import OpCodes

module = dnlib.DotNet.ModuleDefMD.Load(args.file)


def xor_strings(data, key):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(data, key * (len(data) // len(key) + 1)))


def has_target_opcode_sequence(method):
    target_opcode_sequence = [OpCodes.Ldstr, OpCodes.Ldstr, OpCodes.Call, OpCodes.Stelem_Ref]

    if method.HasBody:
        opcode_sequence = [instr.OpCode for instr in method.Body.Instructions]
        for i in range(len(opcode_sequence) - len(target_opcode_sequence) + 1):
            if opcode_sequence[i:i + len(target_opcode_sequence)] == target_opcode_sequence:
                return True
    return False


def process_methods():
    decrypted_strings = []
    check_list = []

    for type in module.GetTypes():
        for method in type.Methods:
            if has_target_opcode_sequence(method) and method.HasBody:
                instructions = list(method.Body.Instructions)
                for i in range(len(instructions) - 1):
                    instr1 = instructions[i]
                    instr2 = instructions[i + 1]

                    if instr1.OpCode == OpCodes.Ldstr and instr2.OpCode == OpCodes.Ldstr:
                        data = instr1.Operand
                        key = instr2.Operand
                        if isinstance(data, str) and isinstance(key, str):
                            decrypted_string = xor_strings(data, key)
                            decrypted_strings.append(decrypted_string)

                    # Only consider ldstr instructions
                    if instr1.OpCode == OpCodes.Ldstr and (instr1.Operand == '1' or instr1.Operand == '0'):
                        check_list.append(instr1.Operand)

    return decrypted_strings, check_list


def print_stealer_configuration(decrypted_strings, xml_declaration_index):
    config_cases = {
        ".": {
            "offsets": [(5, "Telgeram Bot Token"), (7, "Mutex"), (8, "Build Tag"), (4, "Telgeram Chat ID"),
                        (1, "Stealer Tor Folder Name"), (2, "Stealer Folder Name"), (6, "RSAKeyValue")]
        },
        "RSAKeyValue": {
            "offsets": [(1, "Stealer Tor Folder Name"), (2, "Stealer Folder Name"), (3, "Build Version"),
                        (4, "Telgeram Chat ID"), (5, "Telgeram Bot Token"), (6, "Mutex"), (7, "Build Tag")]
        },
        "else": {
            "offsets": [(1, "Stealer Tor Folder Name"), (2, "Stealer Folder Name"), (3, "Build Version"),
                        (4, "Telgeram Chat ID"), (5, "Telgeram Bot Token"), (6, "RSAKeyValue"), (7, "Mutex"),
                        (8, "Build Tag")]
        }
    }

    condition = "." if "." in decrypted_strings[xml_declaration_index - 1] else \
        "RSAKeyValue" if "RSAKeyValue" not in decrypted_strings[xml_declaration_index - 6] else "else"
    offsets = config_cases[condition]["offsets"]
    config_data = {o: decrypted_strings[xml_declaration_index - o] for o, _ in offsets if xml_declaration_index >= o}
    for o, n in offsets:
        print(f"{n}: {config_data.get(o, 'Not Found')}")


def print_features_status(check_list):
    features = [
        (0, "AntiVM"),
        (1, "Resident"),
        (2, "Auto Keylogger"),
        (3, "USB Spread"),
        (4, "Local Users Spread"),
    ]
    for o, n in features:
        status = 'Enabled' if check_list[o] == '1' else 'Disabled'
        print(f"{n}: {status}")


def print_C2(decrypted_strings):
    for data in decrypted_strings:
        if "http://" in data and "127.0.0.1" not in data and "www.w3.org" not in data:
            print("C2: " + data)


def main():
    decrypted_strings, check_list = process_methods()

    xml_declaration = '<?xml version="1.0" encoding="utf-16"?>'
    xml_declaration_index = next((i for i, s in enumerate(decrypted_strings) if xml_declaration in s), None)

    if xml_declaration_index is not None:
        print("Stealer Configuration: " + decrypted_strings[xml_declaration_index])
        print_stealer_configuration(decrypted_strings, xml_declaration_index)

    print_features_status(check_list)
    print_C2(decrypted_strings)


if __name__ == "__main__":
    main()
