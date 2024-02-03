# Author: RussianPanda
# Tested on samples:
# 41a037f09bf41b5cb1ca453289e6ca961d61cd96eeefb1b5bbf153612396d919
# 856a3df5b1930c1fcd5fdce56624f6f26a7e829ea331a182b4a28fd2707436f1
# b2a3112be417feb4f7c3b3f0385bdaee9213bf9cdc82136c05ebebb835c19a65

import hashlib
import re
import zipfile
from string import printable, whitespace
from sys import argv
from typing import BinaryIO, List, Optional

from Crypto.Cipher import AES
from maco.extractor import Extractor
from maco.model.model import ConnUsageEnum, ExtractorModel

assets_file_path = "assets.dat"

class_file = "dynamic/client/Main.class"
search_pattern = rb"assets\.dat.{8}([A-Za-z0-9!@#$%^&*()\-_=+{}\[\]|:;'\"<>,./?]+)"


class DynamicRAT(Extractor):
    family = "DynamicRAT"
    author = "@RussianPanda"
    last_modified = "2023-12-29"
    sharing: str = "TLP:CLEAR"
    reference: str = "https://gi7w0rm.medium.com/dynamicrat-a-full-fledged-java-rat-1a2dabb11694"

    def run(self, stream: BinaryIO, matches: List = []) -> Optional[ExtractorModel]:
        with zipfile.ZipFile(stream, "r") as jar:
            try:
                # Extract the "Main.class" file contents as bytes
                file_bytes = jar.read(class_file)
            except KeyError:
                self.logger.error(f"The file '{class_file}' does not exist in the JAR file.")
                return

            # Find the mention of "assets.dat" and extract the desired string
            match = re.search(search_pattern, file_bytes, flags=re.DOTALL)
            if match:
                extracted_bytes = match.group(1)
                extracted_key = extracted_bytes.decode("utf-8")
                self.logger.info(f"Extracted key: {extracted_key}")
            else:
                self.logger.warning("Key not found in the file.")

        key = hashlib.md5(extracted_key.encode("utf-8")).digest()

        with zipfile.ZipFile(stream, "r") as jar:
            try:
                # Extract the "assets.dat" file contents as bytes
                encrypted_data_bytes = jar.read(assets_file_path)[4:]  # Skip the first four bytes
            except KeyError:
                self.logger.error(f"The file '{assets_file_path}' does not exist in the JAR file.")
                return

        encrypted_data = bytes(encrypted_data_bytes)

        cipher = AES.new(key, AES.MODE_ECB)

        # Decrypt & Sanitize data
        decrypted_data = ""
        for d in (
            cipher.decrypt(encrypted_data)
            .replace(b"\x00", b" ")
            .replace(b"\x0c", b" ")
            .replace(b"\x0b", b" ")
            .decode(errors="ignore")
        ):
            if d in set(printable):
                decrypted_data += d

        decrypted_data = [d.strip(whitespace) for d in decrypted_data.split(" ") if d][-5:]
        config = {
            "c2": decrypted_data[0].rstrip("_"),
            "autostartName": decrypted_data[3],
            "autostartPath": decrypted_data[2],
            "startupFolderName": decrypted_data[4],
        }

        self.logger.info("Decrypted data:", config)
        cfg = ExtractorModel(family=self.family)
        cfg.http.append(cfg.Http(protocol="http", hostname=config.pop("c2"), usage=ConnUsageEnum.c2))
        cfg.other = config
        return cfg


if __name__ == "__main__":
    parser = DynamicRAT()
    file_path = argv[1]

    with open(file_path, "rb") as f:
        result = parser.run(f)
        if result:
            print(result.model_dump_json(indent=2, exclude_none=True, exclude_defaults=True))
        else:
            print("No configuration extracted")
