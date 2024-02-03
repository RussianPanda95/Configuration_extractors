# Author: RussianPanda

# Reference:
# https://research.openanalysis.net/dot%20net/static%20analysis/stormkitty/dnlib/python/research/2021/07/14/dot_net_static_analysis.html
# https://github.com/embee-research/Asyncrat-Venom-Dcrat-Config-Extractor/blob/main/asyncrat-config-extractor.py#L161

# Tested on: bac8861baa346f0ce06c87c33284d478

import base64
import hashlib
import hmac
import re
from sys import argv
from tempfile import NamedTemporaryFile
from typing import BinaryIO, List, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dotnetfile import DotNetPE
from maco.extractor import Extractor
from maco.model import ConnUsageEnum, ExtractorModel


def is_base64(s):
    pattern = r"^[A-Za-z0-9+/]{20,}={0,2}$"
    return re.match(pattern, s) is not None


def decode_and_check_length(base64_string):
    try:
        decoded_bytes = base64.b64decode(base64_string, validate=True)
        return len(decoded_bytes) == 32
    except Exception:
        return False


def get_aes_key(key, salt, keysize):
    key = base64.b64decode(key)
    salt = salt.encode("ascii")
    return hashlib.pbkdf2_hmac("sha1", key, salt, 50000, keysize)


def get_IV(authkey, enc):
    data = base64.b64decode(enc)
    data = data[32:]  # Skip HMAC
    iv = hmac.new(authkey, data, hashlib.sha256).digest()
    return iv[:16]  # First 16 bytes for IV


def aes_decrypt_and_extract_data(enc, key, iv, skip_bytes):
    enc = base64.b64decode(enc)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(enc) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return decrypted_data[skip_bytes:]


class DCRat(Extractor):
    family = "DCRat"
    author = "@RussianPanda"
    last_modified = "2024-02-02"
    sharing: str = "TLP:CLEAR"
    reference: str = (
        "https://www.esentire.com/blog/onlydcratfans-malware-distributed-using-explicit-lures-of-onlyfans-pages-and-other-adult-content"
    )

    def run(self, stream: BinaryIO, matches: List = []) -> Optional[ExtractorModel]:
        with NamedTemporaryFile() as file:
            file.write(stream.read())
            file.flush()

            dotnet_file = DotNetPE(file.name)

        us_stream_strings = dotnet_file.get_user_stream_strings()

        key = None
        for string in us_stream_strings:
            if is_base64(string) and decode_and_check_length(string):
                key = string
                break

        if key is None:
            self.logger.info("No key found.")
            return

        cfg = ExtractorModel(family=self.family)
        skip_bytes = 48

        salt = "DcRatByqwqdanchun"  ## Salt value might be different

        # Generate AES Keys from salt
        key1 = get_aes_key(key, salt, 32)
        key2 = get_aes_key(key, salt, 96)
        key2 = key2[32:]

        decrypted_strings = []

        for string in us_stream_strings:
            if is_base64(string) and string != key:
                try:
                    iv = get_IV(key2, string)
                    decrypted_data = aes_decrypt_and_extract_data(string, key1, iv, skip_bytes)
                    decrypted_strings.append(decrypted_data)
                    cfg.encryption.append(cfg.Encryption(algorithm="AES", key=key1, iv=iv))
                except ValueError as e:
                    if "not a multiple of the block length" in str(e):
                        continue
        try:
            (
                Ports,
                Hosts,
                Version,
                Install,
                MTX,
                Certificate,
                Server_signature,
                Pastebin,
                BSOD,
                Group,
                Anti_Process,
                Anti,
            ) = decrypted_strings
        except ValueError as e:
            self.logger.error(f"Error assigning variables: {e}")
            cfg.decoded_strings = decrypted_strings
            return cfg

        # Variables can be different
        self.logger.info(f"Ports: {Ports}")
        self.logger.info(f"Hosts: {Hosts}")
        self.logger.info(f"Version: {Version}")
        self.logger.info(f"Install: {Install}")
        self.logger.info(f"MTX: {MTX}")
        self.logger.info(f"Certificate: {Certificate}")
        self.logger.info(f"Server_signature: {Server_signature}")
        self.logger.info(f"Pastebin: {Pastebin}")
        self.logger.info(f"BSOD: {BSOD}")
        self.logger.info(f"Group: {Group}")
        self.logger.info(f"Anti_Process: {Anti_Process}")
        self.logger.info(f"Anti: {Anti}")

        cfg.http.append(cfg.Http(hostname=Hosts.decode(), port=Ports.decode(), usage=ConnUsageEnum.c2))
        cfg.version = Version.decode()
        cfg.mutex.append(MTX.decode())
        cfg.campaign_id.append(Group.decode())
        cfg.other = {
            "Install": Install,
            "Certificate": Certificate,
            "Server_signature": Server_signature,
            "Pastebin": Pastebin,
            "BSOD": BSOD,
            "Anti_process": Anti_Process,
            "Anti": Anti,
        }
        return cfg


if __name__ == "__main__":
    parser = DCRat()
    file_path = argv[1]

    with open(file_path, "rb") as f:
        result = parser.run(f)
        if result:
            print(result.model_dump_json(indent=2, exclude_none=True, exclude_defaults=True))
        else:
            print("No configuration extracted")
