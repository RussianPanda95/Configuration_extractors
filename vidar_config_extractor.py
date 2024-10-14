# Author: RussianPanda
# Tested on samples (samples can be found on https://www.unpac.me/):
# 37c74886ce85682039bced4a6423e233aebd962921d9a76008d19ff75483a52c
# 6956fb2dd65d6627c23b680d4149983017bcb8e8b8fc1d30a5210998ca8cf801
# 3a7512884d5e269a6c9d74a0af38c0d4d4b95bdbe5c7cc8d8608e84a725d2134
# bd6370870671ccc61bb9a7ae5d31abc446e893dce15eeaff13deeb64f9317926
# ed28af0855aa6e00776f3633c15663e4a930f54ac399b48369f485e31250849b
# b30bdc75d85cac464fcc59df6a1db4c7ca19c93c2b42db961b41fd814c230d80
# 505e21494deb4e828da8bdfa386fa59a2599f89dc87276f25bd6d923aed13f83
# eba331ce626b9c6ca338c439b608d5234bfd0d0d5408de9e8b64e131435e4216

import re
import struct
from sys import argv
from typing import BinaryIO, List, Optional

import pefile
import requests
from maco.extractor import Extractor
from maco.model import ConnUsageEnum, ExtractorModel


class Vidar(Extractor):
    family = "Vidar"
    author = "@RussianPanda"
    last_modified = "2024-01-20"
    sharing: str = "TLP:CLEAR"
    reference: str = "https://www.esentire.com/blog/esentire-threat-intelligence-malware-analysis-vidar-stealer"
    yara_rule: str = """
rule Vidar
{
    meta:
        author = "kevoreilly,rony"
        description = "Vidar Payload"
        cape_type = "Vidar Payload"
        packed = "0cff8404e73906f3a4932e145bf57fae7a0e66a7d7952416161a5d9bb9752fd8"
    strings:
        $decode = {FF 75 0C 8D 34 1F FF 15 ?? ?? ?? ?? 8B C8 33 D2 8B C7 F7 F1 8B 45 0C 8B 4D 08 8A 04 02 32 04 31 47 88 06 3B 7D 10 72 D8}
        $xor_dec = {0F B6 [0-5] C1 E? ?? 33 ?? 81 E? [0-5] 89 ?? 7C AF 06}
        $wallet = "*wallet*.dat" fullword ascii wide
        $s1 = "\\"os_crypt\\":{\\"encrypted_key\\":\\"" fullword ascii wide
        $s2 = "screenshot.jpg" fullword ascii wide
        $s3 = "\\\\Local State" fullword ascii wide
        $s4 = "Content-Disposition: form-data; name=\\"" fullword ascii wide
        $s5 = "CC\\\\%s_%s.txt" fullword ascii wide
        $s6 = "History\\\\%s_%s.txt" fullword ascii wide
        $s7 = "Autofill\\\\%s_%s.txt" fullword ascii wide
        $s8 = "Downloads\\\\%s_%s.txt" fullword ascii wide
    condition:
        uint16be(0) == 0x4d5a and 6 of them
}
"""

    def run(self, stream: BinaryIO, matches: List = [], download_payload=False) -> Optional[ExtractorModel]:
        pe = pefile.PE(data=stream.read())
        cfg = ExtractorModel(family=self.family)

        # Look for the C2 in the ".rdata" section
        c2 = []
        for s in pe.sections:
            if s.Name.startswith(b".rdata"):
                rdata_start = s.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
                rdata_end = rdata_start + s.Misc_VirtualSize
                rdata_data = s.get_data()

        for m in re.finditer(rb"(https?://[\d\w\.:/?#&+=_-]+)", rdata_data):
            matches = m.group().decode().split("\0")[0]
            if len(matches) > 8:
                c2.append(matches)

        self.logger.info(f"C2: {', '.join(c2)}")
        # Retrieving C2 within the dead drops
        for url in c2:
            cfg.http.append(cfg.Http(uri=url, usage=ConnUsageEnum.c2))
            try:
                response = requests.get(url, timeout=3)
            except requests.Timeout:
                self.logger.info(f"Timed out while connecting to {url}")
                continue

            ip_pattern = (
                r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[^\|]*"
            )
            ip_addresses = set(re.findall(ip_pattern, response.content.decode()))

            if len(ip_addresses) > 0:
                for ip in ip_addresses:
                    self.logger.info(f"C2: {ip}")
                    cfg.http.append(cfg.Http(hostname=ip, usage=ConnUsageEnum.c2))
            else:
                self.logger.info(f"Did not find any C2 in {url}.")

        for s in pe.sections:
            if s.Name.startswith(b".rdata"):
                rdata_start = s.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
                rdata_end = rdata_start + s.Misc_VirtualSize

        try:
            rdata_data = None
            for s in pe.sections:
                if s.Name.startswith(b".rdata"):
                    rdata_start = s.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
                    rdata_end = rdata_start + s.Misc_VirtualSize
                    rdata_data = s.get_data()

            text_data = None
            for s in pe.sections:
                if s.Name.startswith(b".text"):
                    text_data = s.get_data()

            # Find version based on the opcodes
            pattern = rb"\x68(....)\x89\x45\xfc\x88\x06\xe8(....)\x83\xc4\x04|\x68(....)\x8b\xce\x89\x45\xfc\x88\x06"

            results = []
            for m in re.finditer(pattern, text_data):
                if m.group(1):
                    enc_str = struct.unpack("<I", m.group(1))[0]
                elif m.group(2):
                    enc_str = struct.unpack("<I", m.group(2))[0]
                else:
                    enc_str = struct.unpack("<I", m.group(3))[0]
                if rdata_start <= enc_str <= rdata_end:
                    enc_str = pe.get_string_at_rva(enc_str - pe.OPTIONAL_HEADER.ImageBase, 50)
                    results.append(enc_str)

            version = None
            for result in results:
                if "." in result and version is None:
                    version = result
            self.logger.info(f"Version: {version}")
            cfg.version = version

        # Look for the version in ".rdata" if there are no xrefs. NOTE: this might produce False Positive results
        except:
            version = []
            for m in re.finditer(rb"\b\d+\.\d+\b", rdata_data):
                version.append(m.group().replace(b"\x00", b""))
            self.logger.info(f"Version: {(version[2].decode())}")
            cfg.version = version[2].decode()
        return cfg


if __name__ == "__main__":
    import yara

    parser = Vidar()
    file_path = argv[1]

    with open(file_path, "rb") as f:
        result = parser.run(f, matches=yara.compile(source=parser.yara_rule).match(file_path), download_payload=True)
        if result:
            print(result.model_dump_json(indent=2, exclude_none=True, exclude_defaults=True))
        else:
            print("No configuration extracted")
