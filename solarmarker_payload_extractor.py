# Author: RussianPanda
# Tested on sample: 1160da03685be4abedafa4f03b02cdf3f3242bc1d6985187acf281f5c7e46168

import re
from dotnetfile import DotNetPE
from base64 import b64decode
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


from maco.extractor import Extractor
from maco.model import ExtractorModel, ConnUsageEnum
from sys import argv
from tempfile import NamedTemporaryFile
from typing import BinaryIO, List, Optional

class SolarMarker(Extractor):
    family = "SolarMarker"
    author = "@RussianPanda"
    last_modified = "2024-01-20"
    sharing: str = "TLP:CLEAR"
    reference: str = "https://www.esentire.com/blog/esentire-threat-intelligence-malware-analysis-solarmarker"
    yara_rule: str = """
import "pe"
rule  SolarMarker_backdoor {
    meta:
        author = "eSentire TI"
        date = "04/13/2022"
        version = "1.0"
    strings:
        $string1 = "ezkabsr" wide fullword nocase
        $string3 = "deimos.dll" wide fullword nocase
        $string4 = "solarmarker.dat" wide fullword nocase
        $string5 = "dzkabr" wide fullword nocase
        $string6 = "Invoke"
        $string7 = "set_UseShellExecute"
    condition:
        2 of ($string*) and
        (uint16(0) == 0x5A4D or uint32(0) == 0x4464c457f)
}

import "pe"
rule  SolarMarker_payload {
    meta:
        author = "eSentire TI"
        date = "04/13/2022"
        version = "1.0"
    strings:
        $string1 = "IOSdyabisytda" wide fullword nocase
        $string2 = "PowerShell"
        $string3 = "Invoke"
        $string4 = "ProcessStartInfo"
    condition:
        3 of ($string*) and
        (uint16(0) == 0x5A4D or uint32(0) == 0x4464c457f)
}

"""

    def run(self, stream: BinaryIO, matches: List = [], download_payload=False) -> Optional[ExtractorModel]:
        cfg = ExtractorModel(family=self.family)
        # Account for different ways of executing this extractor, both piece-wise and as a whole
        if not matches or (matches[0].rule == "SolarMarker_payload"):
            # We're dealing with the initial payload
            with NamedTemporaryFile("w+b") as file:
                file.write(stream.read())
                file.flush()
                dotnet_file_path = file.name
                dotnet_file = DotNetPE(dotnet_file_path)

            data = dotnet_file.get_user_stream_strings()

            base64_pattern = r"^(?=.{20,})(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
            base64_regex = re.compile(base64_pattern)

            base64_matches = []
            for string in data:
                base64_matches.extend([match.group() for match in base64_regex.finditer(string) if match])

            matches_string = ''.join(base64_matches)

            try:
                decoded_bytes = b64decode(matches_string)
                decoded = decoded_bytes.decode('utf-8')
            except Exception as e:
                print(f"Error while decoding base64 string: {e}")
                decoded = ''

            url_pattern = r"https://[\w\./-]*"
            url_regex = re.compile(url_pattern)

            url_matches = [match.group() for match in url_regex.finditer(decoded) if match]

            server_url = None
            print(url_matches)
            if len(url_matches) >= 2:
                server_url = url_matches[1]
                print("Payload serving URL found:", server_url)
                cfg.http.append(cfg.Http(uri=server_url, usage=ConnUsageEnum.download))

        content = None
        if download_payload:
            # Attempt to download payload from server
            try:
                response = requests.get(server_url, verify=False)

                # If the request is successful, the status code == 200
                if response.status_code == 200:
                    content = response.text
            except requests.exceptions.RequestException as e:
                print(f"Request failed due to an exception: {e}")

        if not content and server_url:
            # Downloading payload from server unsuccessful, quit
            return cfg

        if not content and (matches and matches[0].rule == "SolarMarker_backdoor"):
            # The file provided to the extractor is the backdoor that was downloaded by the server found in the initial payload
            content = stream.read().decode()

        if content:
            pattern = r"FromBase64String\('([^']*)="
            regex = re.compile(pattern)

            base64_payload = [match.group(1) + '=' for match in regex.finditer(content) if match]

            key_pattern = r'\$A\.Key=@\(\[byte\](.*?)\);'
            iv_pattern = r'\$A\.IV=@\(\[byte\](.*?)\);'

            key_match = re.search(key_pattern, content)
            iv_match = re.search(iv_pattern, content)

            encryption = cfg.Encryption(algorithm="AES")

            if key_match:
                key = key_match.group(1)
                key_bytes = bytes([int(x) for x in key.split(',')])
                print('Key:', key)
                encryption.key = key

            if iv_match:
                iv = iv_match.group(1)
                iv_bytes = bytes([int(x) for x in iv.split(',')])
                print('IV:', iv)
                encryption.iv = iv

            for i, b64_str in enumerate(base64_payload):
                try:
                    decoded = b64decode(b64_str)

                    cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv_bytes)
                    decrypted_payload = unpad(cipher.decrypt(decoded), AES.block_size)
                    cfg.binaries.append(
                        cfg.Binary(datatype=cfg.Binary.TypeEnum.payload, data=decrypted_payload, encryption=[encryption])
                    )

                    # Write the second-stage payload to a file
                    with open(f'second_stage_payload.bin', 'wb') as f:
                        f.write(decrypted_payload)
                    print("Success: 'second_stage_payload.bin' has been created")

                except Exception as e:
                    print(f"Error while decrypting base64 string: {e}")
        return cfg


if __name__ == "__main__":
    import yara
    parser = SolarMarker()
    file_path = argv[1]

    with open(file_path, "rb") as f:
        result = parser.run(f, matches=yara.compile(source=parser.yara_rule).match(file_path), download_payload=True)
        if result:
            print(result.model_dump_json(indent=2, exclude_none=True, exclude_defaults=True))
        else:
            print("No configuration extracted")
