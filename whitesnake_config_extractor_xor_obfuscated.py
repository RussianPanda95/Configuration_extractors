# Author: RussianPanda
# Tested on samples:
# f7b02278a2310a2657dcca702188af461ce8450dc0c5bced802773ca8eab6f50
# c219beaecc91df9265574eea6e9d866c224549b7f41cdda7e85015f4ae99b7c7

import os
from pathlib import Path
from sys import argv
from tempfile import NamedTemporaryFile
from typing import BinaryIO, List, Optional

import clr
from maco.extractor import Extractor
from maco.model import ConnUsageEnum, ExtractorModel

dn_lib_found = list(Path("/usr/lib").glob("**/dnlib.dll"))
DNLIB_PACKAGE_PATH = str(dn_lib_found[0]) if dn_lib_found else "dnlib"

DNLIB_PATH = os.environ.get("DNLIB_PATH", DNLIB_PACKAGE_PATH)
if not os.path.exists(DNLIB_PATH):
    raise FileNotFoundError(DNLIB_PATH)
clr.AddReference(DNLIB_PATH)

import dnlib
from dnlib.DotNet import *
from dnlib.DotNet.Emit import OpCodes


def xor_strings(data, key):
    return "".join(chr(ord(a) ^ ord(b)) for a, b in zip(data, key * (len(data) // len(key) + 1)))


def has_target_opcode_sequence(method):
    target_opcode_sequence = [OpCodes.Ldstr, OpCodes.Ldstr, OpCodes.Call, OpCodes.Stelem_Ref]

    if method.HasBody:
        opcode_sequence = [instr.OpCode for instr in method.Body.Instructions]
        for i in range(len(opcode_sequence) - len(target_opcode_sequence) + 1):
            if opcode_sequence[i : i + len(target_opcode_sequence)] == target_opcode_sequence:
                return True
    return False


def process_methods(module):
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
                    if instr1.OpCode == OpCodes.Ldstr and (instr1.Operand == "1" or instr1.Operand == "0"):
                        check_list.append(instr1.Operand)

    return decrypted_strings, check_list


def get_stealer_configuration(decrypted_strings, xml_declaration_index):
    config_cases = {
        ".": {
            "offsets": [
                (5, "Telgeram Bot Token"),
                (7, "Mutex"),
                (8, "Build Tag"),
                (4, "Telgeram Chat ID"),
                (1, "Stealer Tor Folder Name"),
                (2, "Stealer Folder Name"),
                (6, "RSAKeyValue"),
            ]
        },
        "RSAKeyValue": {
            "offsets": [
                (1, "Stealer Tor Folder Name"),
                (2, "Stealer Folder Name"),
                (3, "Build Version"),
                (4, "Telgeram Chat ID"),
                (5, "Telgeram Bot Token"),
                (6, "Mutex"),
                (7, "Build Tag"),
            ]
        },
        "else": {
            "offsets": [
                (1, "Stealer Tor Folder Name"),
                (2, "Stealer Folder Name"),
                (3, "Build Version"),
                (4, "Telgeram Chat ID"),
                (5, "Telgeram Bot Token"),
                (6, "RSAKeyValue"),
                (7, "Mutex"),
                (8, "Build Tag"),
            ]
        },
    }

    condition = (
        "."
        if "." in decrypted_strings[xml_declaration_index - 1]
        else "RSAKeyValue" if "RSAKeyValue" not in decrypted_strings[xml_declaration_index - 6] else "else"
    )
    offsets = config_cases[condition]["offsets"]
    config_data = {o: decrypted_strings[xml_declaration_index - o] for o, _ in offsets if xml_declaration_index >= o}
    readable_config_data = {}
    for o, n in offsets:
        readable_config_data[n] = config_data.get(o, "Not Found")
    return readable_config_data


def get_features_status(check_list):
    features = [
        (0, "AntiVM"),
        (1, "Resident"),
        (2, "Auto Keylogger"),
        (3, "USB Spread"),
        (4, "Local Users Spread"),
    ]
    feature_status = {}
    for o, n in features:
        status = "Enabled" if check_list[o] == "1" else "Disabled"
        feature_status[n] = status
    return feature_status


def filter_C2(data):
    return bool("http://" in data and "127.0.0.1" not in data and "www.w3.org" not in data)


class WhiteSnakeStealer(Extractor):
    family = "WhiteSnake Stealer"
    author = "@RussianPanda"
    last_modified = "2024-02-02"
    sharing: str = "TLP:CLEAR"
    reference: str = "https://russianpanda.com/2023/07/04/WhiteSnake-Stealer-Malware-Analysis/"
    yara_rule: str = """
rule WhiteSnakeStealer {

	meta:
		author = "RussianPanda"
		reference = "https://russianpanda.com/2023/07/04/WhiteSnake-Stealer-Malware-Analysis/"
		description = "Detects WhiteSnake Stealer XOR samples "
		date = "7/4/2023"

	strings:
		$s1 = {FE 0C 00 00 FE 09 00 00 FE 0C 02 00 6F ?? 00 00 0A FE 0C 03 00 61 D1 FE 0E 04 00 FE}
		$s2 = {61 6e 61 6c 2e 6a 70 67}
	condition:
		all of ($s*) and filesize < 600KB

}
"""

    def run(self, stream: BinaryIO, matches: List = []) -> Optional[ExtractorModel]:
        with NamedTemporaryFile() as file:
            file.write(stream.read())
            file.flush()

            module = dnlib.DotNet.ModuleDefMD.Load(file.name)

        decrypted_strings, check_list = process_methods(module)

        xml_declaration = '<?xml version="1.0" encoding="utf-16"?>'
        xml_declaration_index = next((i for i, s in enumerate(decrypted_strings) if xml_declaration in s), None)

        if xml_declaration_index is not None:
            cfg = ExtractorModel(family=self.family)
            self.logger.info("Stealer Configuration: " + decrypted_strings[xml_declaration_index])
            cfg.binaries.append(
                cfg.Binary(data=decrypted_strings[xml_declaration_index].encode(), datatype=cfg.Binary.TypeEnum.config)
            )
            config_data = get_stealer_configuration(decrypted_strings, xml_declaration_index)
            cfg.mutex.append(config_data["Mutex"])
            cfg.other["raw_config"] = config_data
        else:
            return

        feature_status = get_features_status(check_list)
        cfg.other["features"] = feature_status
        for c2 in filter(filter_C2, decrypted_strings):
            self.logger.info(f"C2 : {c2}")
            cfg.http.append(cfg.Http(uri=c2, usage=ConnUsageEnum.c2))

        return cfg


if __name__ == "__main__":
    parser = WhiteSnakeStealer()
    file_path = argv[1]

    with open(file_path, "rb") as f:
        result = parser.run(f)
        if result:
            print(result.model_dump_json(indent=2, exclude_none=True, exclude_defaults=True))
        else:
            print("No configuration extracted")
