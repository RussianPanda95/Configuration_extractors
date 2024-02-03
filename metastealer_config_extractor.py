import base64
import os
import re
from pathlib import Path
from sys import argv
from tempfile import NamedTemporaryFile
from typing import BinaryIO, List, Optional

import clr
from maco.extractor import Extractor
from maco.model import ExtractorModel

# Check default location from package install
dn_lib_found = list(Path("/usr/lib").glob("**/dnlib.dll"))
DNLIB_PACKAGE_PATH = str(dn_lib_found[0]) if dn_lib_found else "dnlib"

DNLIB_PATH = os.environ.get("DNLIB_PATH", DNLIB_PACKAGE_PATH)
if not os.path.exists(DNLIB_PATH):
    raise FileNotFoundError(DNLIB_PATH)
clr.AddReference(DNLIB_PATH)

import dnlib
from dnlib.DotNet import ModuleDefMD
from dnlib.DotNet.Emit import OpCodes


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


class MetaStealer(Extractor):
    family = "MetaStealer"
    author = "@RussianPanda"
    last_modified = "2024-02-02"
    sharing: str = "TLP:CLEAR"
    reference: str = "https://russianpanda.com/2023/11/20/MetaStealer-Redline%27s-Doppelganger/"
    yara_rule: str = """
import "pe"
rule MetaStealer {

	meta:
		author = "RussianPanda"
    decription = "Detects the old version of MetaStealer 11-2023"
		date = "11/16/2023"

	strings:
		$s1 = "FileScannerRule"
		$s2 = "MSObject"
		$s3 = "MSValue"
		$s4 = "GetBrowsers"
		$s5 = "Biohazard"

	condition:
		4 of ($s*)
		and pe.imports("mscoree.dll")
}
"""

    def run(self, stream: BinaryIO, matches: List = []) -> Optional[ExtractorModel]:
        with NamedTemporaryFile() as file:
            file.write(stream.read())
            file.flush()

            extracted_strings = extract_strings_from_dotnet(file.name)

        cfg = ExtractorModel(family=self.family)
        b64 = r"^[A-Za-z0-9+/]+={0,2}$"
        b64_strings = []
        last_b64_index = -1

        for i, string in enumerate(extracted_strings):
            if re.match(b64, string) and len(string) % 4 == 0 and len(string) > 20:
                b64_strings.append(string)
                last_b64_index = i

        xor_key_match = None
        if last_b64_index != -1 and last_b64_index + 2 < len(extracted_strings):
            xor_key_match = extracted_strings[last_b64_index + 2]

        if b64_strings:
            string = b64_strings[0]
            self.logger.info("Authentication token:", string)
            cfg.other["Authentication token"] = string

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
                    string_result = final_result.decode("utf-8")
                    self.logger.info("Decrypted String:", string_result)
                    cfg.encryption.append(cfg.Encryption(algorithm="XOR", key=xor_key))
                    cfg.decoded_strings.append(string_result)
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
                        string_result = final_result.decode("utf-8")
                        self.logger.info("Decrypted String:", string_result)
                        cfg.encryption.append(cfg.Encryption(algorithm="XOR", key=xor_key))
                        cfg.decoded_strings.append(string_result)
                    except Exception as e:
                        self.logger.info(f"Error in decryption: {e}")
                for string in b64_strings:
                    try:
                        dec_Data = base64.b64decode(string)
                        xor_result = xor_data(dec_Data, xor_key)
                        final_result = base64.b64decode(xor_result)
                        string_result = final_result.decode("utf-8")
                        self.logger.info("Decrypted String:", string_result)
                        cfg.encryption.append(cfg.Encryption(algorithm="XOR", key=xor_key))
                        cfg.decoded_strings.append(string_result)
                    except Exception as e:
                        continue

        return cfg


if __name__ == "__main__":
    parser = MetaStealer()
    file_path = argv[1]

    with open(file_path, "rb") as f:
        result = parser.run(f)
        if result:
            print(result.model_dump_json(indent=2, exclude_none=True, exclude_defaults=True))
        else:
            print("No configuration extracted")
