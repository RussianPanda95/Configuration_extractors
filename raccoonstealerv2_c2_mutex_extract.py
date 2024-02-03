# Tested on the latest unpacked/unobfuscated builds using the XOR instead of RC4

import binascii
import re
import struct
from sys import argv
from typing import BinaryIO, List, Optional

import pefile
from maco.extractor import Extractor
from maco.model import ConnUsageEnum, ExtractorModel


class RaccoonStealer(Extractor):
    family = "RaccoonStealer"
    author = "@RussianPanda"
    last_modified = "2024-01-20"
    sharing: str = "TLP:CLEAR"
    yara_rule: str = """
rule RaccoonStealer {

	meta:
		author = "RussianPanda"
		decription = "Detects Raccoon Stealer v2.3.1.1"
        	reference = "https://www.esentire.com/blog/esentire-threat-intelligence-malware-analysis-raccoon-stealer-v2-0"
		date = "1/8/2024"
		hash = "c6d0d98dd43822fe12a1d785df4e391db3c92846b0473b54762fbb929de6f5cb"
	strings:
	        $s1 = {8B 0D [2] 41 00 A3 [3] 00}
	        $s2 = "MachineGuid"
	        $s3 = "SELECT name_on_card, card_number_encrypted, expiration_month, expiration_year FROM credit_cards"
	        $s4 = "SELECT service, encrypted_token FROM token_service"
	        $s5 = "&configId="
	        $s6 = "machineId="
 	condition:
		all of ($s*) and #s1 > 10
        	and uint16(0) == 0x5A4D
		and filesize < 5MB
}

rule RaccoonStealerv2 {
	meta:
		author = "RussianPanda"
		date = "04/17/2023"
		description = "Detects the latest unpacked/unobfuscated build 2.1.0-4"
	strings:
		$pattern1 = {B9 ?? ?? ?? 00 E8 ?? ?? ?? 00 ?? ?? 89 45 E8}
		$pattern2 = {68 ?? ?? ?? 00 ?? 68 01 00 1F 00}
		$pattern3 = {68 ?? ?? ?? 00 ?? ?? 68 01 00 1F 00 FF 15 64 ?? ?? 00}
		$m1 = {68 ?? ?? ?? 00 ?? 00 68 01 00 1f 00 ff 15 64 ?? ?? 00}
		$m2 = {68 ?? ?? ?? 00 ?? 68 01 00 1f 00 ff 15 64 ?? ?? 00}
	condition:
		2 of ($pattern*) and uint16(0) == 0x5A4D and 1 of ($m*) and uint32(uint32(0x3C)) == 0x00004550 and filesize < 200KB
}
"""

    def run(self, stream: BinaryIO, matches: List = []) -> Optional[ExtractorModel]:
        pe = pefile.PE(data=stream.read())

        pe.relocate_image(0)

        def xor_decrypt(data, key):
            out = []
            for i in range(len(data)):
                out.append(data[i] ^ key[i % len(key)])
            return out

        rdata_start = None
        rdata_end = None

        for s in pe.sections:
            if s.Name.startswith(b".rdata"):
                rdata_start = s.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
                rdata_end = rdata_start + s.Misc_VirtualSize

        assert rdata_start is not None

        text_data = None

        for s in pe.sections:
            if s.Name.startswith(b".text"):
                text_data = s.get_data()

        assert text_data is not None

        pattern = rb"\x6A(.)\xBA(....)\xB9(....)\xE8(....)"
        pattern2 = rb"\x68(....).\x68\x01\x00\x1f\x00|\x68(....)..\x68\x01\x00\x1f\x00"

        enc_str_strip = None
        key = None
        mutex = None

        enc_strings = []
        for m in re.finditer(pattern, text_data):
            str_len = struct.unpack("B", m.group(1))[0]
            str = struct.unpack("<I", m.group(3))[0]
            enc_str = struct.unpack("<I", m.group(2))[0]

            # Retrieving the encoded string
            if rdata_start <= enc_str <= rdata_end:
                enc_str = pe.get_data(enc_str - pe.OPTIONAL_HEADER.ImageBase, str_len)
                if len(enc_str) >= 32:
                    enc_str_strip = enc_str[: enc_str.index(b"\x00")]
                    self.logger.info(f"Encoded string: {enc_str_strip}")

            # Retrieving the XOR key
            if rdata_start <= str <= rdata_end and str_len == 0x40:
                key = pe.get_data(str - pe.OPTIONAL_HEADER.ImageBase, str_len)
                break

        decrypt_me = xor_decrypt(enc_str_strip, key)
        decr_str = "".join(map(chr, decrypt_me))

        cfg = ExtractorModel(family=self.family, version="2")

        # Find last index of "/"
        slash_strip = decr_str.rfind("/")
        if slash_strip != -1:
            # Keep everything before the last "/"
            decr_str = decr_str[: slash_strip + 1]

        self.logger.info(f"C2: {decr_str}")
        cfg.http.append(cfg.Http(uri=decr_str, usage=ConnUsageEnum.c2))
        key_hex = binascii.hexlify(key).decode("utf-8")
        self.logger.info(f"XOR Key: {key_hex[:46]}")
        cfg.encryption.append(cfg.Encryption(algorithm="XOR", key=key_hex))

        # Retrieving the Mutex/User-Agent string
        for m in re.finditer(pattern2, text_data):
            if m.group(1):
                enc_str = struct.unpack("<I", m.group(1))[0]
            else:
                enc_str = struct.unpack("<I", m.group(2))[0]

            if rdata_start <= enc_str <= rdata_end:
                enc_str = pe.get_data(enc_str - pe.OPTIONAL_HEADER.ImageBase)
                mutex = enc_str[:28].decode("utf-8")

        self.logger.info(f"Mutex/User-Agent: {mutex}")
        cfg.mutex.append(mutex)
        return cfg


if __name__ == "__main__":
    parser = RaccoonStealer()
    file_path = argv[1]

    with open(file_path, "rb") as f:
        result = parser.run(f)
        if result:
            print(result.model_dump_json(indent=2, exclude_none=True, exclude_defaults=True))
        else:
            print("No configuration extracted")
