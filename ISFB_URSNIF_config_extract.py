import re
import struct
from sys import argv
from typing import BinaryIO, List, Optional

import malduck
from maco.extractor import Extractor
from maco.model import ConnUsageEnum, ExtractorModel


class Ursnif(Extractor):
    family = "Ursnif"
    author = "@RussianPanda"
    last_modified = "2024-01-20"
    sharing: str = "TLP:CLEAR"
    yara_rule: str = """
rule UrsnifV3
{
    meta:
        author = "kevoreilly"
        description = "UrsnifV3 Payload"
        cape_type = "UrsnifV3 Payload"
        packed = "75827be0c600f93d0d23d4b8239f56eb8c7dc4ab6064ad0b79e6695157816988"
        packed = "5d6f1484f6571282790d64821429eeeadee71ba6b6d566088f58370634d2c579"
    strings:
        $crypto32_1 = {8B C3 83 EB 01 85 C0 75 0D 0F B6 16 83 C6 01 89 74 24 14 8D 58 07 8B C2 C1 E8 07 83 E0 01 03 D2 85 C0 0F 84 AB 01 00 00 8B C3 83 EB 01 85 C0 89 5C 24 20 75 13 0F B6 16 83 C6 01 BB 07 00 00 00}
        $crypto32_2 = {8B 45 ?? 0F B6 3? FF 45 [2-4] 8B C? 23 C? 40 40 D1 E? 7?}
        $crypto32_3 = {F6 46 03 02 75 5? 8B 46 10 40 50 E8 [10-12] 74 ?? F6 46 03 01 74}
        $crypto32_4 = {C7 44 24 10 01 00 00 00 8B 4? 10 [12] 8B [2] 89 01 8B 44 24 10 5F 5E 5B 8B E5 5D C2 0C 00}
        $cpuid = {8B C4 FF 18 8B F0 33 C0 0F A2 66 8C D8 66 8E D0 8B E5 8B C6 5E 5B 5D C3}
        $cape_string = "cape_options"
    condition:
        uint16(0) == 0x5A4D and 1 of ($crypto32_*) and $cpuid and not $cape_string
}
"""

    def run(self, stream: BinaryIO, matches: List = None) -> Optional[ExtractorModel]:
        data = stream.read()
        # decompressing aplib from the extracted blobs
        jj_structure = []

        for i in range(len(data)):
            if data[i : i + 2] == b"JJ":
                jj_structure.append(data[i : i + 20])
        extracted_blob_one = data[43520 : 43520 + 511]
        blob = malduck.aplib.decompress(extracted_blob_one)
        convert_bytes_to_str = blob.decode(errors="replace")

        # grabbing the C2 information
        C2_table = []
        matches = re.finditer(r"([-\w]+(\.[-\w]+)+)", convert_bytes_to_str)
        for m in matches:
            C2_table.append(m.group(0))
        del C2_table[0]

        # grabbing wordlist
        extracted_blob_two = data[44032 : 44032 + 475]
        blob_two = malduck.aplib.decompress(extracted_blob_two)
        wordlist = blob_two.decode(errors="replace").strip("\r\n").split("\r\n")
        self.logger.info(wordlist)
        del wordlist[0]

        # extracting the blobs and outputting the results
        cfg = ExtractorModel(family=self.family)
        for i in range(len(jj_structure)):
            xor_key = struct.unpack("<I", jj_structure[i][4:8])[0]
            self.logger.info(f"XOR Key: {xor_key}")
            cfg.encryption.append(cfg.Encryption(algorithm="XOR", key=str(xor_key)))
            hash_offset = struct.unpack("<I", jj_structure[i][8:12])[0]
            hash_hex = hex(hash_offset)
            self.logger.info(f"Hash: {hash_hex}")
            if hash_offset == 2410798561:
                self.logger.info(f"C2 Table: {C2_table} at offset " + hex(43520))
                cfg.http = [cfg.Http(hostname=i, usage=ConnUsageEnum.c2) for i in C2_table]
            if hash_offset == 1760278915:
                self.logger.info(f"WORDLIST: {wordlist} at offset " + hex(44032))
                cfg.other["wordlist"] = wordlist

            blob_offset = struct.unpack("<I", jj_structure[i][12:16])[0] - 8704
            blob_size = struct.unpack("<I", jj_structure[i][16:20])[0]
        return cfg


if __name__ == "__main__":
    parser = Ursnif()
    file_path = argv[1]

    with open(file_path, "rb") as f:
        result = parser.run(f)
        if result:
            print(result.model_dump_json(indent=2, exclude_none=True, exclude_defaults=True))
        else:
            print("No configuration extracted")
