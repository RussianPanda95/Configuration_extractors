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


def find_embedded_binaries(filename):
    PE_signature = b'MZ'

    with open(filename, 'rb') as f:
        data = f.read()

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

def analyze_binary(data):
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
    print(f"C2: {cleaned_string}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 darkvnc_config_extract.py <filename>")
        sys.exit(1)

    binary_data = find_embedded_binaries(sys.argv[1])  
    if binary_data:
        analyze_binary(binary_data)
    else:
        print("No binary with the specified pattern found")