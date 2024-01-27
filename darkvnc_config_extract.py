# Author: RussianPanda

# Tested on samples:
# 9442ece5ae6face31fba5809c824003c
# 3c74dccd06605bcf527ffc27b3122959
# 87c04f01ee46a0ac344128599099bd59
# f031a1ba221d29f52d16397560ae801b
# f85ae229fe7a4fde53c3b624dca754ad
# e3677f3bc40f060c93433e659bd0add8
# b50905d057a282b606c94e1986d92177
# 3951017cf3e81be09e6a866db472a4a4
# f15eefe467952b3946c35a578308bbda
# 5d6f3fa9c4667ad08fdffe4a1822c268
# 643fd55381fc0261f8420ae772251ff4
# 28e30fdb1b118c1574c07623d8c9f178
# 2d84aff562319b25bbef718dde079d43
# b8a9215b1d7e35698f757e20e1fc47bc
# 1b7e8401b1b7176921050f46e01bf796

import yara
import capstone
import pefile
import sys

from maco.extractor import Extractor
from maco.model import ExtractorModel, ConnUsageEnum
from sys import argv
from tempfile import NamedTemporaryFile
from typing import BinaryIO, List, Optional


skip_rule = """
rule skip_pattern {
    strings:
        $skip_this = {56 43 32 30 58 43 30 30 55}
    condition:
        $skip_this
}
"""

darkvnc_rule = """
rule darkvnc_rule: bar {
    strings:
        $data = {C7 84 24 B8 00 00 00 10 00 00 00 B8 69 00 00 00 }
    condition:
        $data
}
"""

skip_rules = yara.compile(source=skip_rule)
analyze_rules = yara.compile(source=darkvnc_rule)

def get_virtual_address_from_offset(pe, offset):
    for section in pe.sections:
        if section.PointerToRawData <= offset < section.PointerToRawData + section.SizeOfRawData:
            return pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + (offset - section.PointerToRawData)
    return None


def find_embedded_binaries(data):
    PE_signature = b'MZ'

    offset = 0
    while True:
        offset = data.find(PE_signature, offset)
        if offset == -1:
            print("No more PE signatures found.")
            break

        # Extract the embedded binary data
        embedded_binary_data = data[offset:]

        try:
            pe = pefile.PE(data=embedded_binary_data)
        except pefile.PEFormatError:
            offset += 1
            continue

        # Check if the binary contains the skip pattern
        if skip_rules.match(data=embedded_binary_data):
            pass
        else:
            return embedded_binary_data

        offset += 1

    return None

class DarkVNC(Extractor):
    family = "DarkVNC"
    author = "@RussianPanda"
    last_modified = "2024-01-21"
    sharing: str = "TLP:CLEAR"
    yara_rule: str = """
rule DarkVNC {
	meta:
		author = "RussianPanda"
		description = "Detects DarkVNC"
		date = "1/15/2024"
		hash = "3c74dccd06605bcf527ffc27b3122959"
	strings:
		$s1 = {66 89 84 24 ?? 00 00 00 B8 ?? 00 00 00}
		$s2 = {66 31 14 41 48}
		$s3 = "VncStopServer"
		$s4 = "VncStartServer"
	condition:
		uint16(0) == 0x5A4D and
		3 of them and filesize < 700KB
}
"""

    def run(self, stream: BinaryIO, matches: List = []) -> Optional[ExtractorModel]:
        data = stream.read()
        matches = analyze_rules.match(data=data)
        pe = pefile.PE(data=data)



        # Check if it's a 32-bit or 64-bit binary
        mode = capstone.CS_MODE_32 if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386'] else capstone.CS_MODE_64
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, mode)
        disassembler.detail = True

        extracted_chars = []
        key = None

        for match in matches:
            for string_data in match.strings:
                offset = string_data[0]
                virtual_address = get_virtual_address_from_offset(pe, offset)

                instructions_count = 0
                for i in disassembler.disasm(data[offset:offset + 1000], virtual_address):
                    if instructions_count >= 55:
                        break

                    if i.mnemonic == "mov":
                        if i.op_str.startswith("eax, "):
                            char_value = chr(int(i.op_str.split(", ")[1], 16))
                            extracted_chars.append(char_value)
                        elif i.op_str.startswith("dl, "):
                            key = chr(int(i.op_str.split(", ")[1], 16))

                    #print(f"0x{i.address:X}:\t{i.mnemonic}\t{i.op_str}")
                    instructions_count += 1

        encoded_str = ''.join(extracted_chars)
        decrypted_string = ''.join([chr(ord(char) ^ ord(key)) for char in encoded_str])
        cleaned_string = ''.join([char for char in decrypted_string if char.isdigit() or char == "." or char == ":"])
        ip, port = cleaned_string.rsplit(':', 1)
        cfg = ExtractorModel(family=self.family,
                             tcp=[ExtractorModel.Connection(server_ip=ip,
                                                            server_port=int(port),
                                                            usage=ConnUsageEnum.c2)])
        print(f"C2: {cleaned_string}")
        return cfg


if __name__ == "__main__":
    parser = DarkVNC()
    file_path = argv[1]

    with open(file_path, "rb") as f:
        result = parser.run(f)
        if result:
            print(result.model_dump_json(indent=2, exclude_none=True, exclude_defaults=True))
        else:
            print("No configuration extracted")
