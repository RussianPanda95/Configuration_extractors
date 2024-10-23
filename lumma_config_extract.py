import re
import base64
from typing import BinaryIO, List, Optional
from maco.extractor import Extractor
from maco.model import ConnUsageEnum, ExtractorModel

def extract_b64(file_data: bytes, min_length=60, max_length=100):
    """Extract base64-like strings from the file."""
    try:
        data = file_data.decode('utf-8')
    except UnicodeDecodeError:
        data = file_data.decode('latin1')

    pattern = r'(?:(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)'
    matches = re.findall(pattern, data)
    filtered_matches = [match for match in matches if min_length <= len(match) <= max_length]
    return filtered_matches

def find_id_pattern(file_data: bytes):
    """Search for the Build ID or User ID based on a specific pattern."""
    id_pattern = b'\x66\x69\x6E\x64\x69\x6E\x67\x20\x63\x65\x6E\x74\x72\x61\x6C\x20\x64\x69\x72\x65\x63\x74\x6F\x72\x79\x00'
    match = re.search(id_pattern, file_data)
    if match:
        start_index = match.end()
        build_id = bytearray()
        while start_index < len(file_data) and file_data[start_index] != 0x00:
            build_id.append(file_data[start_index])
            start_index += 1
        build_id_str = build_id.decode('utf-8', errors='ignore').strip()
        if '--' in build_id_str:
            return f"Build ID: {build_id_str.strip()}"
        else:
            return f"User ID: {build_id_str.strip()}"
    return None

def xor_decrypt(encoded_str):
    """Decrypt the encoded string using XOR and return a domain."""
    try:
        dec_data = base64.b64decode(encoded_str)
        key = dec_data[:32]
        data = dec_data[32:]
        decrypted = bytearray()
        for i in range(len(data)):
            decrypted.append(data[i] ^ key[i % len(key)])
        decrypted_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in decrypted)
        domain_match = re.search(r'([a-zA-Z0-9-]+\.[a-zA-Z]{2,})', decrypted_str)
        return domain_match.group(1) if domain_match else None
    except Exception as e:
        print(f"Error decrypting data: {e}")
        return None

class LummaExtractor(Extractor):
    family = "Lumma"
    author = "@RussianPanda"
    last_modified = "2024-10-15"
    sharing = "TLP:CLEAR"
    reference = "https://www.esentire.com/blog/lummac2-malware-and-malicious-chrome-extension-delivered-via-dll-side-loading"
    yara_rule = """
rule LummaC2 {
    meta:
        description = "Detects LummaC2 Stealer"
        author = "RussianPanda"
        date = "2024-09-12"
        hash = "988f54f9694dd1ae701bacec3b83c752"

    strings:
        $s1 = {0F B6 [2-6] 83 ?? 1F} // Decrypting the C2s
        $s2 = {F3 A5 8B 74 24 F8 8B 7C 24 F4 8D 54 24 04 FF 54 24 FC C3} // Heaven's Gate

    condition:
        uint16(0) == 0x5A4D and all of them
}
"""

    def run(self, stream: BinaryIO, matches: List = []) -> Optional[ExtractorModel]:
        """Run the analysis process and extract configuration from Lumma."""
        try:
            file_data = stream.read()
            base64_strs = extract_b64(file_data)
            domains = []

            # Decrypt domains
            for string in base64_strs:
                result = xor_decrypt(string)
                if result:
                    domains.append(result)

            # Find User/Build ID
            id_value = find_id_pattern(file_data)

            # Create the ExtractorModel
            if domains or id_value:
                cfg = ExtractorModel(family=self.family)
                unique_domains = list(set(domains))

                for domain in unique_domains:
                    cfg.http.append(ExtractorModel.Http(
                        hostname=domain,
                        usage=ConnUsageEnum.c2
                    ))

                if id_value:
                    cfg.identifier.append(id_value)

                return cfg
            else:
                self.logger.info("No configuration extracted.")
                return None

        except Exception as e:
            self.logger.error(f"Error during extraction: {e}")
            return None

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Static analysis of a file")
    parser.add_argument("file_path", help="The path to the file to analyze")
    args = parser.parse_args()

    lumma_extractor = LummaExtractor()
    with open(args.file_path, "rb") as f:
        result = lumma_extractor.run(f)
        if result:
            print(result.model_dump_json(indent=2, exclude_none=True, exclude_defaults=True))
        else:
            print("No configuration extracted")
