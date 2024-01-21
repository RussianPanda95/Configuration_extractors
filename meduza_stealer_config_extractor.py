# Author: RussianPanda
# Reference: https://research.openanalysis.net/risepro/stealer/config/triage/2023/06/15/risepro.html
# Tested on samples:
# 702abb15d988bba6155dd440f615bbfab9f3c0ed662fc3e64ab1289a1098af98
# 2ad84bfff7d5257fdeb81b4b52b8e0115f26e8e0cdaa014f9e3084f518aa6149
# f0c730ae57d07440a0de0889db93705c1724f8c3c628ee16a250240cc4f91858
# 1c70f987a0839d11826f053ae90e81a277fa154f5358303fe9a511dbe8b529f2
# cbc07d45dd4967571f86ae75b120b620b701da11c4ebfa9afcae3a0220527972
# afbf62a466552392a4b2c0aa8c51bf3bde84afbe5aa84a2483dc92e906421d0a
# 6d8ed1dfcb2d8a9e3c2d51fa106b70a685cbd85569ffabb5692100be75014803
# ddf3604bdfa1e5542cfee4d06a4118214a23f1a65364f44e53e0b68cbfc588ea
# 91efe60eb46d284c3cfcb584d93bc5b105bf9b376bee761c504598d064b918d4
# f575eb5246b5c6b9044ea04610528c040c982904a5fb3dc1909ce2f0ec15c9ef
# a73e95fb7ba212f74e0116551ccba73dd2ccba87d8927af29499bba9b3287ea7

import os
import re
import struct
import pefile
from capstone import *
from capstone.x86 import *


from maco.extractor import Extractor
from maco.model import ExtractorModel, ConnUsageEnum
from sys import argv
from tempfile import NamedTemporaryFile
from typing import BinaryIO, List, Optional


class MeduzaStealer(Extractor):
    family = "MeduzaStealer"
    author = "@RussianPanda"
    last_modified = "2024-01-20"
    sharing: str = "TLP:CLEAR"
    yara_rule: str = """
rule MeduzaStealer {
    meta:
        author = "RussianPanda"
        reference = "https://russianpanda.com/2023/06/28/Meduza-Stealer-or-The-Return-of-The-Infamous-Aurora-Stealer/"
        description = "Detects MeduzaStealer"
        date = "6/27/2023"

    strings:
        $s1 = {74 69 6D 65 7A 6F 6E 65}
        $s2 = {75 73 65 72 5F 6E 61 6D 65}
        $s3 = {67 70 75}
        $s4 = {63 75 72 72 65 6E 74 5F 70 61 74 68 28 29}
        $s5 = {C5 FD EF}
        $s6 = {66 0F EF}

    condition:
        all of them and filesize < 700KB
}

rule MeduzaStealer_1 {
    meta:
        author = "RussianPanda"
        description = "Detects MeduzaStealer 1-2024"
    reference = "https://russianpanda.com/2023/06/28/Meduza-Stealer-or-The-Return-of-The-Infamous-Aurora-Stealer/"
        date = "01/01/2024"

    strings:
        $s1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 57 69 6e 55 70 64 61 74 65 2e 65 78 65}
    $s2 = {0f 57 ?? ?? ?? 00 00 66 0f 7f 85 ?? ?? 00 00}
    $s3 = {48 8d 15 ?? ?? 05 00 49 8b cf}
    $s4 = {48 8d 0d ?? ?? 06 00 ff 15 ?? ?? 06 00}

    condition:
        3 of ($s*) and filesize < 1MB
}
"""

    def run(self, stream: BinaryIO, matches: List = []) -> Optional[ExtractorModel]:
        # Commit file to disk to be analyzed
        with NamedTemporaryFile("wb") as file:
            file.write(stream.read())
            file.flush()

            result = self.define_binary(file.name)
            if result:
                cfg = ExtractorModel(family=self.family)
                # Add C2 to output
                cfg.http.append(cfg.Http(hostname=result['c2'].replace('\u0000', ''), usage=ConnUsageEnum.c2))
                # Add XOR key to output
                cfg.encryption.append(cfg.Encryption(algorithm="XOR", key=result["xor_key"]))
                if "build" in result:
                    cfg.other["build"] = result["build"]
                return cfg

    def read_string(self, filename, offset):
        try:
            with open(filename, "rb") as f:
                f.seek(offset)
                result = []
                while True:
                    byte = f.read(1)
                    if byte == b'\x00':
                        break
                    result.append(byte.decode('ISO-8859-1'))
            return "".join(result)
        except Exception as e:
            self.logger.info(f"Could not read the string due to: {e}")
            return "The string could not be identified."

    def analyze_32bit_binary(self, filename):
        pe = pefile.PE(filename)
        config = {}

        text_section = next((section for section in pe.sections if section.Name.startswith(b'.text')), None)

        image_base = pe.OPTIONAL_HEADER.ImageBase
        section_rva = text_section.VirtualAddress
        section_data = text_section.get_data()

        pattern = rb'\x68.{2}\x49\x00\xB9.{2}\x4A\x00\xC7\x05'
        pattern2 = rb'\x68.{2}\x49\x00\x8d\x4d\x80'

        pattern_find = re.finditer(pattern, section_data, re.DOTALL)

        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True
        md.skipdata = True

        instructions = []
        for match in pattern_find:
            scan_end = match.start()
            for inst in md.disasm(section_data[scan_end-0x400:scan_end], image_base + section_rva + scan_end - 0x400):
                instructions.append(inst)

        data_values = []
        instructions_count = 0
        end_of_interesting_code = False
        for inst in reversed(instructions):
            if inst.bytes[0] == 0xCC:
                end_of_interesting_code = True
            if end_of_interesting_code:
                instructions_count += 1
                if (
                    instructions_count > 445
                    and instructions_count < 525
                    and inst.mnemonic == 'mov'
                    and inst.operands[1].type == X86_OP_IMM
                    and inst.operands[0].type == X86_OP_MEM
                    and not any(register in str(inst.operands[0]) for register in ['eax', 'ebx', 'ecx', 'edx'])
                ):
                    second_operand = inst.operands[1].imm
                    if second_operand != 0x00000000:
                        merged_data = struct.pack("<I", second_operand)
                        data_values.insert(0, merged_data)

        merged_value = b''.join(data_values)
        half_length = len(merged_value) // 2
        data = merged_value[:half_length]
        key = merged_value[half_length:]

        self.logger.info("Data:", data.hex())
        self.logger.info("Key:", key.hex())
        config["xor_key"] = key.hex()

        xor_result = bytes(a ^ b for a, b in zip(data, key))
        decrypted_c2 = xor_result.decode("utf-8")

        self.logger.info("Decrypted C2:", decrypted_c2)
        config["c2"] = decrypted_c2

        found_push = False

        # Iterate over all sections
        for section in pe.sections:
            section_rva = section.VirtualAddress
            section_data = section.get_data()

            matches2 = re.finditer(pattern2, section_data, re.DOTALL)
            instructions = []
            additional_bytes = 0x50
            for match in matches2:
                scan_start = match.start()
                scan_end = scan_start + additional_bytes
                for inst in md.disasm(section_data[scan_start:scan_end], image_base + section_rva + scan_start):
                    instructions.append(inst)
                    if inst.mnemonic == 'push' and not found_push:
                        va = inst.operands[0].imm
                        #  converts the Virtual Address (VA) of the string to a file offset
                        offset = pe.get_offset_from_rva(va - image_base)
                        string = self.read_string(filename, offset)
                        self.logger.info(f"Build name: {string}")
                        config["build"] = string
                        found_push = True
                        break
        return config

    def analyze_64bit_binary(self, filename):
        pe = pefile.PE(filename)
        config = {}

        text_section = next((section for section in pe.sections if section.Name.startswith(b'.text')), None)

        image_base = pe.OPTIONAL_HEADER.ImageBase
        section_rva = text_section.VirtualAddress
        section_data = text_section.get_data()

        pattern3 = rb'\x48.{4}\x07\x00\x48.{4}\x08\x00'

        matches = re.finditer(pattern3, section_data, re.DOTALL)

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        md.skipdata = True

        instructions_count = 0
        instructions = []

        for match in matches:
            scan_end = match.start()
            for inst in md.disasm(section_data[scan_end-0x400:scan_end], image_base + section_rva + scan_end - 0x400):
                instructions_count += 1
                if instructions_count > 163 and instructions_count < 180:
                    instructions.append(inst)

        data_values = []
        for inst in reversed(instructions):
            if inst.mnemonic == 'movabs':
                second_operand = inst.operands[1].imm
                try:
                    data_x64 = struct.pack("<q", second_operand)
                    data_values.insert(0, data_x64)
                except struct.error:
                    self.logger.info(f"Value {second_operand} is too large to pack.")
                    # self.logger.info(inst)

        merged_value = b''.join(data_values)
        half_length = len(merged_value) // 2
        data = merged_value[:half_length]
        key = merged_value[half_length:]

        self.logger.info("Data:", data.hex())
        self.logger.info("Key:", key.hex())
        config["xor_key"] = key.hex()
        xor_result = bytes(a ^ b for a, b in zip(data, key))
        # Print readable string
        decrypted_c2 = xor_result.decode("utf-8")
        self.logger.info("Decrypted C2:", decrypted_c2)
        config["c2"] = decrypted_c2

        pattern3 = rb'\x48.{4}\x05\x00\x48.{4}\x00\x00\xE8.{2}\xfe\xff'
        matches_64 = re.finditer(pattern3, section_data, re.DOTALL)

        instructions_count = 0
        instructions = []

        for match in matches_64:
            scan_end = match.start()
            for inst in md.disasm(section_data[scan_end:scan_end + 0x400], image_base + section_rva + scan_end):
                instructions.append(inst)

                if inst.mnemonic == 'lea' and inst.reg_name(inst.operands[0].reg) == 'rdx':
                    displacement = inst.operands[1].mem.disp
                    string_address = inst.address + inst.size + displacement
                    rva_string_address = string_address - image_base
                    # Making sure we're not trying to access a negative offset
                    if rva_string_address - section_rva >= 0:
                        # Mapping RVA to raw offset
                        raw_offset = pe.get_offset_from_rva(rva_string_address)

                        if raw_offset is not None:
                            string = self.read_string(filename, raw_offset)
                            if string == "timezone" or string == "system" or string == 'time' or string == 'computer_name' or string == 'cpu' or string == 'core' or string == 'ram' or string == 'gpu' or string == 'user_name' or string == 'os' or string == 'execute_path':
                                break
                            self.logger.info("Build name: ", string)
                            config["build"] = string

                if len(instructions) >= 1:
                    break
        return config

    def define_binary(self, filename):
        pe = pefile.PE(filename)

        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            return self.analyze_64bit_binary(filename)
        elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            return self.analyze_32bit_binary(filename)
        else:
            self.logger.info(f"Unsupported machine type: {pe.FILE_HEADER.Machine}")


if __name__ == "__main__":
    parser = MeduzaStealer()
    file_path = argv[1]

    with open(file_path, "rb") as f:
        result = parser.run(f)
        if result:
            print(result.model_dump_json(indent=2, exclude_none=True, exclude_defaults=True))
        else:
            print("No configuration extracted")
