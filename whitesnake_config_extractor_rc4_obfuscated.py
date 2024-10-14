# Author: RussianPanda

import logging
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

logging.basicConfig(filename="app.log", filemode="w", format="%(name)s - %(levelname)s - %(message)s")


def Ichduzekkvzjdxyftabcqu(A_0, A_1):
    try:
        string_builder = []
        num = 0
        array = list(range(256))

        for i in range(256):
            array[i] = i

        for j in range(256):
            num = (ord(A_1[j % len(A_1)]) + array[j] + num) % 256
            num2 = array[j]
            array[j] = array[num]
            array[num] = num2

        for k in range(len(A_0)):
            num3 = k % 256
            num = (array[num3] + num) % 256
            num2 = array[num3]
            array[num3] = array[num]
            array[num] = num2
            decrypted_char = chr(ord(A_0[k]) ^ array[(array[num3] + array[num]) % 256])
            string_builder.append(decrypted_char)

        return "".join(string_builder)
    except Exception as e:
        logging.error("Error occurred in Ichduzekkvzjdxyftabcqu: " + str(e))
        return None


def has_target_opcode_sequence(method):
    target_opcode_sequence = [OpCodes.Ldstr, OpCodes.Ldstr, OpCodes.Call, OpCodes.Stelem_Ref]

    if method.HasBody:
        # Get the sequence of OpCodes in the method
        opcode_sequence = [instr.OpCode for instr in method.Body.Instructions]

        # Check if the target sequence is present in the opcode sequence
        for i in range(len(opcode_sequence) - len(target_opcode_sequence) + 1):
            if opcode_sequence[i : i + len(target_opcode_sequence)] == target_opcode_sequence:
                return True

    return False


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
		description = "WhiteSnake Stealer"
		date = "7/4/2023"

	strings:
		$s1 = {73 68 69 74 2e 6a 70 67}
		$s2 = {FE 0C ?? 00 20 00 01 00 00 3F ?? FF FF FF 20 00 00 00 00 FE 0E ?? 00 38 ?? 00 00 00 FE 0C}
		$s3 = "qemu" wide
		$s4 = "vbox" wide
	condition:
		all of ($s*) and filesize < 300KB

}
"""

    def run(self, stream: BinaryIO, matches: List = []) -> Optional[ExtractorModel]:
        with NamedTemporaryFile() as file:
            file.write(file.read())
            file.flush()

            module = dnlib.DotNet.ModuleDefMD.Load(file.name)

        ldstr_counter = 0
        decrypted_strings = []

        for type in module.GetTypes():
            for method in type.Methods:
                if method.HasBody and has_target_opcode_sequence(method):
                    instructions = list(method.Body.Instructions)
                    for i, instr in enumerate(instructions):
                        # Only consider ldstr instructions
                        if instr.OpCode == OpCodes.Ldstr:
                            ldstr_counter += 1
                            if ldstr_counter > 21:
                                if instr.Operand == "1" or instr.Operand == "0":
                                    decrypted_strings.append(instr.Operand)
                                elif i + 1 < len(instructions):
                                    encrypted_data = instr.Operand
                                    rc4_key = instructions[i + 1].Operand
                                    if isinstance(encrypted_data, str) and isinstance(rc4_key, str):
                                        decrypted_data = Ichduzekkvzjdxyftabcqu(encrypted_data, rc4_key)
                                        if decrypted_data:
                                            decrypted_strings.append(decrypted_data)

        xml_declaration = '<?xml version="1.0" encoding="utf-16"?>'
        xml_declaration_index = next((i for i, s in enumerate(decrypted_strings) if xml_declaration in s), None)

        cfg = ExtractorModel(family=self.family)
        if xml_declaration_index is not None:
            self.logger.info("Stealer Configuration: " + decrypted_strings[xml_declaration_index])
            cfg.binaries.append(
                cfg.Binary(datatype=cfg.Binary.TypeEnum.config, data=decrypted_strings[xml_declaration_index].encode())
            )
            offsets = [(11, "RSAKeyValue"), (12, "Mutex"), (13, "Build Tag")]
            config_data = {
                o: decrypted_strings[xml_declaration_index - o] for o, _ in offsets if xml_declaration_index >= o
            }
            for o, n in offsets:
                print(f"{n}: {config_data.get(o, 'Not Found')}")
                cfg.other[n] = config_data.get(o, "Not Found")

            offsets = [
                (10, "Telgeram Bot Token"),
                (9, "Telgeram Chat ID"),
                (1, "Stealer Tor Folder Name"),
                (2, "Stealer Folder Name"),
                (3, "Stealer Version"),
            ]

            features = [
                (4, "Local Users Spread"),
                (5, "USB Spread"),
                (6, "Auto Keylogger"),
                (7, "Execution Method"),
                (8, "AntiVM"),
            ]

            config_data = {
                o: decrypted_strings[xml_declaration_index - o] for o, _ in offsets if xml_declaration_index >= o
            }
            for o, n in offsets:
                print(f"{n}: {config_data.get(o, 'Not Found')}")
                cfg.other[n] = config_data.get(o, "Not Found")

            config_data = {
                o: decrypted_strings[xml_declaration_index - o] for o, _ in features if xml_declaration_index >= o
            }
            for o, n in features:
                status = "Enabled" if config_data.get(o, "0") == "1" else "Not Enabled"
                print(f"{n}: {status}")
                cfg.other[n] = config_data.get(o, "Not Found")

        for data in decrypted_strings:
            if "http://" in data and "127.0.0.1" not in data and "www.w3.org" not in data:
                print("C2: " + data)
                cfg.http.append(cfg.Http(uri=data, usage=ConnUsageEnum.c2))
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
