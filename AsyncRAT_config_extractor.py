# Author: RussianPanda

import os
import re
from base64 import b64decode
from sys import argv
from tempfile import NamedTemporaryFile
from typing import BinaryIO, List

from backports.pbkdf2 import pbkdf2_hmac
from Crypto.Cipher import AES
from dotnetfile import DotNetPE
from maco.extractor import Extractor
from maco.model import ConnUsageEnum, ExtractorModel

SALT = b"\xbf\xeb\x1e\x56\xfb\xcd\x97\x3b\xb2\x19\x02\x24\x30\xa5\x78\x43\x00\x3d\x56\x44\xd2\x1e\x62\xb9\xd4\xf1\x80\xe7\xe6\xc3\x39\x41"


def decrypt_AES(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


# look for base64 pattern
BASE64_RE = r"^(?=.{20,})(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"

B64_VALUES = [
    "Ports",
    "Hosts",
    "Version",
    "Install",
    "Key",
    "MTX",
    "Certificate",
    "ServerSignature",
    "Anti",
    "Pastebin",
    "BDOS",
    "Group",
]
PLAINTEXT_VALUES = ["InstallFolder", "InstallFile", "Delay", "Hwid"]


class AsyncRAT(Extractor):
    family = "AsyncRAT"
    author = "@RussianPanda"
    last_modified = "2023-12-28"
    sharing: str = "TLP:CLEAR"
    reference: str = "https://malpedia.caad.fkie.fraunhofer.de/details/win.asyncrat"
    yara_rule: str = """
    rule win_asyncrat_w0 {
    meta:
        description = "detect AsyncRat in memory"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "memory scan"
        reference = "internal research"
        hash = "1167207bfa1fed44e120dc2c298bd25b7137563fdc9853e8403027b645e52c19"
        hash = "588c77a3907163c3c6de0e59f4805df41001098a428c226f102ed3b74b14b3cc"
        source = "https://github.com/JPCERTCC/MalConfScan/blob/master/yara/rule.yara"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.asyncrat"
        malpedia_rule_date = "20201006"
        malpedia_hash = ""
        malpedia_version = "20201006"
        malpedia_license = "CC NC-BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $salt = {BF EB 1E 56 FB CD 97 3B B2 19 02 24 30 A5 78 43 00 3D 56 44 D2 1E 62 B9 D4 F1 80 E7 E6 C3 39 41}
        $b1 = {00 00 00 0D 53 00 48 00 41 00 32 00 35 00 36 00 00} $b2 = {09 50 00 6F 00 6E 00 67 00 00}
        $s1 = "pastebin" ascii wide nocase
        $s2 = "pong" wide $s3 = "Stub.exe" ascii wide

    condition:
        ($salt and (2 of ($s*) or 1 of ($b*))) or (all of ($b*) and 2 of ($s*))
}
"""

    def run(self, stream: BinaryIO, matches: List = []):
        with NamedTemporaryFile() as file:
            file.write(stream.read())
            file.flush()

            dotnet_pe = DotNetPE(path=file.name)
            data = dotnet_pe.get_user_stream_strings()

            """
            // Token: 0x04000045 RID: 69
            private const int KeyLength = 32;

            // Token: 0x04000046 RID: 70
            private const int AuthKeyLength = 64;

            // Token: 0x04000047 RID: 71
            private const int IvLength = 16;

            // Token: 0x04000048 RID: 72
            private const int HmacSha256Length = 32;
            """

            b64dec = data[1:2][0]
            b64dec = b64decode(b64dec)
            key_enc = data[7:8][0]
            key_dec = b64decode(key_enc).decode()
            key = bytes(key_dec, "utf-8")

            dec_key = pbkdf2_hmac("sha1", key, SALT, 50000, 32)
            iv = b64dec[32:48]

            value_strings = []
            counter_list = []

            counter = 0
            for value in data:
                if re.search(BASE64_RE, value):
                    value_decode = b64decode(value)

                    value_decrypt = decrypt_AES(value_decode, dec_key, iv)
                    value_strip = value_decrypt[48:]
                    value_strip = value_strip.decode()
                    value_strip = re.sub(r"[^a-zA-Z0-9 _.,|]+", "", value_strip)
                    value_strings.append(value_strip)

                else:
                    counter += 1
                    if 2 <= counter <= 5:
                        counter_list.append(value)
                    elif counter > 5:
                        break

            flat_config = dict()
            for i in range(len(counter_list)):
                flat_config[PLAINTEXT_VALUES[i]] = counter_list[i]

            # appending to the key item
            value_strings[4] = data[7:8][0]

            for i in range(len(value_strings)):
                flat_config[B64_VALUES[i]] = value_strings[i]

            if flat_config:
                # Parse into MACO format
                cfg = ExtractorModel(family=self.family, version=flat_config.pop("Version"))

                # Encryption
                cfg.encryption.append(
                    cfg.Encryption(algorithm="AES 256", key=b64decode(flat_config.pop("Key")).decode())
                )

                # HTTP connection to C2 server
                cfg.http.append(
                    ExtractorModel.Http(
                        hostname=flat_config.pop("Hosts"),
                        port=flat_config.pop("Ports"),
                        usage=ConnUsageEnum.c2,
                        protocol="http",
                    )
                )

                # Mutex
                cfg.mutex.append(flat_config.pop("MTX"))

                # Sleep Delay
                cfg.sleep_delay = flat_config.pop("Delay")

                # Install Path
                cfg.paths.append(
                    cfg.Path(
                        path=os.path.join(flat_config.pop("InstallFolder"), flat_config.pop("InstallFile")),
                        usage=cfg.Path.UsageEnum.install,
                    )
                )

                # Put the rest of the data in "other"
                cfg.other = flat_config

                return cfg


if __name__ == "__main__":
    parser = AsyncRAT()
    file_path = argv[1]

    with open(file_path, "rb") as f:
        print(parser.run(f).model_dump_json(indent=2, exclude_none=True, exclude_defaults=True))
