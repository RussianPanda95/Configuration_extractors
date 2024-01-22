from dotnetfile import DotNetPE
from Crypto.Cipher import AES
from backports.pbkdf2 import pbkdf2_hmac
from base64 import b64decode
import os
import re

from maco.extractor import Extractor
from maco.model import ExtractorModel, ConnUsageEnum
from sys import argv
from tempfile import NamedTemporaryFile
from typing import BinaryIO, List, Optional

SALT = b'\xbf\xeb\x1e\x56\xfb\xcd\x97\x3b\xb2\x19\x02\x24\x30\xa5\x78\x43\x00\x3d\x56\x44\xd2\x1e\x62\xb9\xd4\xf1\x80\xe7\xe6\xc3\x39\x41'

B64_VALUES = ['Version', 'Hosts', 'Subdirectory', 'InstallName', 'Mutex', 'StartupKey', 'Tag', 'LogDirectoryName']


def decrypt_AES(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def get_value_strings(value_decode_list, key, iv):
    non_printable_ascii = re.compile('[^\x20-\x7E]')
    value_strings = []
    for value_decode in value_decode_list:
        try:
            value_decrypt = decrypt_AES(value_decode, key, iv)
            value_strip = value_decrypt[48:]
            value_strip = value_strip.decode()
            # Remove non-printable ASCII characters
            value_strip = non_printable_ascii.sub('', value_strip)
            # Replace "\n" with an empty string
            value_strip = value_strip.replace('\n', '')
            value_strings.append(value_strip)
        except:
            pass
    return value_strings

class QuasarRAT(Extractor):
    family = "QuasarRAT"
    author = "@RussianPanda"
    last_modified = "2024-01-21"
    sharing: str = "TLP:CLEAR"
    yara_rule: str = """
rule QuasarRAT {
   meta:
      description = "Detects Quasar RAT"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
      date = "2017-04-07"
      hash1 = "0774d25e33ca2b1e2ee2fafe3fdbebecefbf1d4dd99e6460f0bc8713dd0fd740"
      hash2 = "1ce40a89ef9d56fd32c00db729beecc17d54f4f7c27ff22f708a957cd3f9a4ec"
      hash3 = "515c1a68995557035af11d818192f7866ef6a2018aa13112fefbe08395732e89"
      hash4 = "f08db220df716de3d4f63f3007a03f902601b9b32099d6a882da87312f263f34"
      id = "36220de3-aa1a-5c34-adae-432d939c811e"
   strings:
      $s1 = "DoUploadAndExecute" fullword ascii
      $s2 = "DoDownloadAndExecute" fullword ascii
      $s3 = "DoShellExecute" fullword ascii
      $s4 = "set_Processname" fullword ascii

      $op1 = { 04 1e fe 02 04 16 fe 01 60 }
      $op2 = { 00 17 03 1f 20 17 19 15 28 }
      $op3 = { 00 04 03 69 91 1b 40 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and all of ($s*) or all of ($op*) )
}

rule QuasarRAT_2 {
   meta:
      description = "Detects Quasar RAT"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
      date = "2017-04-07"
      super_rule = 1
      hash1 = "0774d25e33ca2b1e2ee2fafe3fdbebecefbf1d4dd99e6460f0bc8713dd0fd740"
      hash2 = "515c1a68995557035af11d818192f7866ef6a2018aa13112fefbe08395732e89"
      hash3 = "f08db220df716de3d4f63f3007a03f902601b9b32099d6a882da87312f263f34"
      id = "0ca795c5-3631-5a99-8675-37558485f478"
   strings:
      $x1 = "GetKeyloggerLogsResponse" fullword ascii
      $x2 = "get_Keylogger" fullword ascii
      $x3 = "HandleGetKeyloggerLogsResponse" fullword ascii

      $s1 = "DoShellExecuteResponse" fullword ascii
      $s2 = "GetPasswordsResponse" fullword ascii
      $s3 = "GetStartupItemsResponse" fullword ascii
      $s4 = "<GetGenReader>b__7" fullword ascii
      $s5 = "RunHidden" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and $x1 ) or ( all of them )
}
"""

    def run(self, stream: BinaryIO, matches: List = []) -> Optional[ExtractorModel]:


        with NamedTemporaryFile() as file:
            file.write(stream.read())
            file.flush()

            dotnet_file = DotNetPE(file.name)
            data = dotnet_file.get_user_stream_strings()

            base64_pattern = r"^(?!.*//)(?=.{20,})(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"

            matches = []

            for value in data:
                if re.search(base64_pattern, value):
                    matches.append(value)

            value_decode_list = []
            for value in matches:
                if re.search(base64_pattern, value):
                    value_decode = b64decode(value)
                    value_decode_list.append(value_decode)

            key_enc = matches[8]
            key_enc = bytes(key_enc, 'utf-8')
            key_size = 16
            key = pbkdf2_hmac("sha1", key_enc, SALT, 50000, key_size)
            key_s = matches[2]
            iv = value_decode_list[0][32:48]

            value_strings = get_value_strings(value_decode_list, key, iv)
            if len(value_strings) < 2:
                # Not enough values extracted, try again with 32 bytes key length
                # reference: https://research.openanalysis.net/quasar/chaos/rat/ransomware/2023/04/13/quasar-chaos.html
                # using different key size, 32 bytes

                key_size = 32
                key_enc = matches[6]
                key_enc = bytes(key_enc, 'utf-8')
                key = pbkdf2_hmac("sha1", key_enc, SALT, 50000, key_size)
                key_s = matches[6]
                value_strings = get_value_strings(value_decode_list, key, iv)

            encryption_key = matches[8]
            authkey = matches[3]

            if key_size == 16:
                del value_strings[2]

            config_dict = {"Key": key_s, "EncryptionKey": encryption_key, "Authkey": authkey}
            config_dict.update({B64_VALUES[i]: value_string for i, value_string in enumerate(value_strings)})
            [self.logger.info(f"{k}: {v}")for k, v in config_dict.items()]

            cfg = ExtractorModel(family=self.family)

            # Set version
            cfg.version = config_dict.pop('Version')

            # Append C2 hosts
            [cfg.http.append(cfg.Http(uri=c2, usage=ConnUsageEnum.c2)) for c2 in config_dict.pop('Hosts', '').split(';')]

            # Append install path
            cfg.paths.append(cfg.Path(
                path=os.path.join(config_dict.pop('Subdirectory'), config_dict.pop('InstallName')),
                usage=cfg.Path.UsageEnum.install)
            )

            # Append mutex
            cfg.mutex.append(config_dict.pop('Mutex', ''))

            # Append encryption details used for comms
            cfg.encryption.append(
                cfg.Encryption(
                    algorithm="AES",
                    key=config_dict.pop('Key'),
                    iv=str(iv),
                    usage=cfg.Encryption.UsageEnum.communication)
            )

            # Append registry keys used
            cfg.registry.append(cfg.Registry(
                key=f"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\{config_dict.pop('StartupKey')}",
                usage=cfg.Registry.UsageEnum.persistence
                )
            )

            # Remaining data wll be in other
            cfg.other = config_dict
            return cfg


if __name__ == "__main__":
    parser = QuasarRAT()
    file_path = argv[1]

    with open(file_path, "rb") as f:
        result = parser.run(f)
        if result:
            print(result.model_dump_json(indent=2, exclude_none=True, exclude_defaults=True))
        else:
            print("No configuration extracted")
