import base64
import json
import re
from sys import argv
from typing import BinaryIO, List

from maco.extractor import Extractor
from maco.model import ConnUsageEnum, ExtractorModel

# Reference: Borrowed a nice regex pattern to grab the IPs from OALabs https://research.openanalysis.net/golang/titan/stealer/python/research/ida/goresym/alphagolang/2022/12/01/titan_stealer.html :P

pattern_c2 = rb"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"

patterns = [
    rb"[A-Za-z0-9+/]{4}(?:[A-Za-z0-9+/]{4})*(?=[0-9]+)",
    rb"(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)",
]


class Aurora(Extractor):
    family = "Aurora Stealer"
    author = "@RussianPanda"
    last_modified = "2023-12-29"
    sharing: str = "TLP:CLEAR"
    reference: str = "https://www.esentire.com/blog/esentire-threat-intelligence-malware-analysis-aurora-stealer"
    yara_rule: str = """
rule  AuroraStealer {
    meta:
        author = "eSentire Threat Intelligence"
        description = "Detects the Build/Group IDs if present / detects an unobfuscated AuroraStealer binary; tested on version 22.12.2022 and March 2023 update"
        date = "3/24/2023"

    strings:
        $b1 = { 48 8D 0D ?? ?? 04 00 E8 ?? ?? EF FF }
        $b2 = { 48 8D 0D ?? ?? 05 00 E8 ?? ?? EF FF }
        $ftp = "FOUND FTP"
        $go = "Go build ID"
        $machineid = "MachineGuid"

    condition:
        3 of them
}
"""

    def run(self, stream: BinaryIO, matches: List = []) -> ExtractorModel:
        data = stream.read()

        matches = []
        for pattern in patterns:
            matches.extend(re.findall(pattern, data))

        matches = [match for match in matches if len(match) > 90]

        found_match_config = False
        found_match_loader = False
        found_match_grabber = False
        found_match_PowerShell = False
        grabber_found = False

        # Search for the configuration module in the binary
        config_match = re.search(rb"eyJCdWlsZElEI[^&]{0,400}", data)
        cfg = None
        if config_match:
            found_match_config = True
            matched_string_h = config_match.group(0)
            matched_string = config_match.group(0).decode("utf-8")
            decoded_str = base64.b64decode(matched_string)
            self.logger.info(f"Configuration found: {decoded_str.decode('utf-8')}")
            self.logger.info("Configuration module offset:", hex(data.find(matched_string_h)))

            cfg = ExtractorModel(family=self.family)
            config_json = json.loads(decoded_str)

            # Extract C2
            c2 = config_json.pop("IP", "")
            if ":" in c2:
                # C2 contains port information
                ip, port = c2.rsplit(":", 1)
                cfg.tcp.append(cfg.Connection(server_ip=ip, server_port=port, usage=ConnUsageEnum.c2))
            else:
                # C2 doesn't contain port, default to 8081
                cfg.tcp.append(cfg.Connection(server_ip=c2, server_port="8081", usage=ConnUsageEnum.c2))

            # Add all other configuration details under "other"
            cfg.other = {k: v for k, v in config_json.items() if v}

        else:
            self.logger.warning("Configuration not found")

        # Extracting the modules
        for match in matches:
            match_str = match.decode("utf-8")
            decoded_str = base64.b64decode(match_str)

            if b"DW" in decoded_str:
                found_match_loader = True
                data_dict = json.loads(decoded_str)
                for elem in data_dict:
                    if elem["Method"] == "DW":
                        self.logger.info("Loader module found:", elem)
                self.logger.info("Loader module offset:", hex(data.find(match)))

            if b"PS" in decoded_str:
                found_match_PowerShell = True
                data_dict = json.loads(decoded_str)
                for elem in data_dict:
                    if elem["Method"] == "PS":
                        self.logger.info("PowerShell module found:", elem)
                self.logger.info("PowerShell module offset:", hex(data.find(match)))

            if b"Path" in decoded_str:
                found_match_grabber = True
                grabber_found = True
                break
            else:
                grabber_match = re.search(b"W3siUGF0aCI6.{116}", data)
                if grabber_match:
                    found_match_grabber = True
                    encoded_string = grabber_match.group(0)
                    decoded_str = base64.b64decode(encoded_string)
                    grabber_str = decoded_str[:95].decode("utf-8", errors="ignore")
                    cleanup_str = grabber_str.split("[")[-1].split("]")[0]

                    if not grabber_found:
                        grabber_found = True
                        self.logger.info("Grabber module found:", cleanup_str)
                        self.logger.info("Graber module offset:", hex(data.find(encoded_string)))

        if not found_match_config:
            self.logger.info("No configurartion found")
        if not found_match_loader:
            self.logger.info("No Loader module found")
        if not found_match_PowerShell:
            self.logger.info("No PowerShell module found")
        if not found_match_grabber:
            self.logger.info("No Grabber module found")

        # Extract the C2
        matches = re.findall(pattern_c2, data)

        if matches:
            last_match = matches[-1]
            offset = data.find(last_match)
            self.logger.info(f"C2 found at: {last_match.decode('utf-8')} at offset {hex(offset)}")
        else:
            self.logger.info("No C2 found")

        return cfg


if __name__ == "__main__":
    parser = Aurora()
    file_path = argv[1]

    with open(file_path, "rb") as f:
        print(parser.run(f).model_dump_json(indent=2, exclude_none=True, exclude_defaults=True))
