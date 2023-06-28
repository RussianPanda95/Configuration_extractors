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

import os
import re
import struct
import pefile
from capstone import *
from capstone.x86 import *

def read_string(filename, offset):
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
        print(f"Could not read the string due to: {e}")
        return "The string could not be identified."


def analyze_32bit_binary(filename):
    pe = pefile.PE(filename)

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

    print("Data:", data.hex())
    print("Key:", key.hex())

    xor_result = bytes(a ^ b for a, b in zip(data, key))
    decrypted_c2 = xor_result.decode("utf-8")

    print("Decrypted C2:", decrypted_c2)

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
                    string = read_string(filename, offset)
                    print(f"Build name: {string}")
                    found_push = True
                    break
     

def analyze_64bit_binary(filename):
    pe = pefile.PE(filename)

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
                print(f"Value {second_operand} is too large to pack.")
                #print(inst)

    merged_value = b''.join(data_values)
    half_length = len(merged_value) // 2
    data = merged_value[:half_length]
    key = merged_value[half_length:]

    print("Data:", data.hex())
    print("Key:", key.hex())
    xor_result = bytes(a ^ b for a, b in zip(data, key))
    # Print readable string
    decrypted_c2 = xor_result.decode("utf-8")
    print("Decrypted C2:", decrypted_c2)

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
                        string = read_string(filename, raw_offset)
                        if string == "timezone" or string == "system" or string == 'time' or string == 'computer_name' or string == 'cpu' or string == 'core' or string == 'ram' or string == 'gpu' or string == 'user_name' or string == 'os' or string == 'execute_path':
                            break
                        print("Build name: ", string)

            if len(instructions) >= 1:
                break


def define_binary(filename):
    pe = pefile.PE(filename)

    if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
        analyze_64bit_binary(filename)
    elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
        analyze_32bit_binary(filename)
    else:
        print(f"Unsupported machine type: {pe.FILE_HEADER.Machine}")

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python3 meduza_config_extractor.py <filename>")
        sys.exit(1)

    filename = sys.argv[1]

    if not os.path.isfile(filename):
        print(f"File not found: {filename}")
        sys.exit(1)

    define_binary(filename)
