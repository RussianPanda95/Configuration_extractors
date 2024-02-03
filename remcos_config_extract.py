# Author: RussianPanda
# Tested on sample: 63a2dcb487d0d875688f4e4d5251a93b

import string
from sys import argv
from typing import BinaryIO, List, Optional

import pefile
from Crypto.Cipher import ARC4
from maco.extractor import Extractor
from maco.model import ConnUsageEnum, ExtractorModel


def decrypt_rc4_data(data, key):
    cipher = ARC4.new(key)
    return cipher.decrypt(data)


def extract_all_rcdata(pe_data):
    pe = pefile.PE(data=pe_data)
    rcdata_values = []

    # Check if the PE file has a resource directory
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        # Traverse the resource directory
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if entry.id == pefile.RESOURCE_TYPE["RT_RCDATA"]:
                for resource in entry.directory.entries:
                    for entry_lang in resource.directory.entries:
                        data_rva = entry_lang.data.struct.OffsetToData
                        size = entry_lang.data.struct.Size
                        data = pe.get_memory_mapped_image()[data_rva : data_rva + size]
                        rcdata_values.append(data)

    return rcdata_values


class Remcos(Extractor):
    family = "Remcos"
    author = "@RussianPanda"
    last_modified = "2024-02-02"
    sharing: str = "TLP:CLEAR"
    reference: str = "https://www.esentire.com/blog/remcos-rat"

    def run(self, stream: BinaryIO, matches: List = []) -> Optional[ExtractorModel]:

        rcdata_contents = extract_all_rcdata(stream.read())

        if rcdata_contents:
            cfg = ExtractorModel(family=self.family)
            for rcdata in rcdata_contents:
                if len(rcdata) > 1:
                    key_length = rcdata[0]
                    key = rcdata[1 : 1 + key_length]
                    encrypted_data = rcdata[1 + key_length :]
                    decrypted_data = decrypt_rc4_data(encrypted_data, key)
                    decoded_data = decrypted_data.decode("utf-8", "replace")
                    printable = set(string.printable)  #
                    filtered_data = list(filter(lambda x: x in printable, decoded_data))
                    self.logger.info("Decrypted Config:", "".join(filtered_data))
                    cfg.decoded_strings = filtered_data
            return cfg
        else:
            self.logger.info("No RCDATA found")


if __name__ == "__main__":
    parser = Remcos()
    file_path = argv[1]

    with open(file_path, "rb") as f:
        result = parser.run(f)
        if result:
            print(result.model_dump_json(indent=2, exclude_none=True, exclude_defaults=True))
        else:
            print("No configuration extracted")
