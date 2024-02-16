# Author: RussianPanda
# Tested on samples (samples can be found on VirusTotal):
# 59b1721e3c3a42079673bebeb36e8c47dad88e93bdebcd6bb1468c4ca1235732

import struct
from sys import argv
from typing import BinaryIO, List, Optional

import pefile
from maco.extractor import Extractor
from maco.model import ExtractorModel


class IcedID(Extractor):
    family = "IcedID"
    author = "@RussianPanda"
    last_modified = "2023-12-29"
    sharing: str = "TLP:CLEAR"
    reference: str = "https://www.esentire.com/blog/esentire-threat-intelligence-malware-analysis-gootloader-and-icedid"
    yara_rule: str = """
rule IcedID_loader {
  meta:
        description = "Detects IcedID loader"
        author = "eSentire TI"
        date = "06/13/2022"

  strings:
        $a = "oCookie: _s=" wide fullword nocase
        $a1 = "Cookie: __gads=" wide fullword nocase
        $a2 = "oCookie: _s=" wide fullword nocase
        $a3 = "__io=" wide fullword nocase
        $a4 = {63 3A 5C 50 72 6F 67 72 61 6D 44 61 74 61 5C}
        $a5 = {3B 00 20 00 5F 00 67 00 61 00 3D}
        $a6 = {3B 00 20 00 5F 00 67 00 69 00 64 00 3D}
        $a7 = {3B 00 20 00 5F 00 67 00 61 00 74 00 3D}
  condition:
        all of ($a*) and filesize < 20KB
    }
"""

    def run(self, stream: BinaryIO, matches: List = None) -> Optional[ExtractorModel]:
        pe = pefile.PE(data=stream.read())
        for s in pe.sections:
            if s.SizeOfRawData > 256:
                data_start = s.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
                data_end = data_start + s.Misc_VirtualSize
                data = s.get_data()

        bytes = bytearray()

        for i in range(32):
            bytes.append(data[i] ^ data[i + 64])

        key = data[:32].hex()
        campaign_id = struct.unpack("<I", bytes[:4])[0]
        c2 = bytes[4:].split(b"\x00")[0].decode()
        cfg = None
        if c2:
            cfg = ExtractorModel(family=self.family)
            self.logger.info(f"C2: {c2}")
            cfg.http.append(cfg.Http(uri=c2))
            self.logger.info(f"Campaign ID: {campaign_id}")
            cfg.campaign_id.append(str(campaign_id))
            self.logger.info(f"Key: {key}")
            cfg.encryption.append(cfg.Encryption(key=key))
        return cfg


if __name__ == "__main__":
    parser = IcedID()
    file_path = argv[1]

    with open(file_path, "rb") as f:
        result = parser.run(f)
        if result:
            print(result.model_dump_json(indent=2, exclude_none=True, exclude_defaults=True))
        else:
            print("No configuration extracted")
