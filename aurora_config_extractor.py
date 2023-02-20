import re
import base64
import json
import argparse

# Reference: Borrowed a nice regex pattern to grab the IPs from OALabs https://research.openanalysis.net/golang/titan/stealer/python/research/ida/goresym/alphagolang/2022/12/01/titan_stealer.html :P 
# Aurora Stealer uses 8081 for the C2 port, it cannot be customized
pattern_c2 = rb'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\:8081'
 
patterns = [
    rb'[A-Za-z0-9+/]{4}(?:[A-Za-z0-9+/]{4})*(?=[0-9]+)',
    rb'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)'
]

parser = argparse.ArgumentParser()
parser.add_argument('--file', required=True)
args = parser.parse_args()

with open(args.file, "rb") as f:
    data = f.read()

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
    config_match = re.search(rb'eyJCdWlsZElEI[^&]{0,400}', data)
    if config_match:
        found_match_config = True
        matched_string_h = config_match.group(0)
        matched_string = config_match.group(0).decode('utf-8')
        decoded_str = base64.b64decode(matched_string)
        print(f"Configuration found: {decoded_str.decode('utf-8')}")
        print("Configuration module offset:", hex(data.find(matched_string_h)))
    else:
        print("Configuration not found")

    # Extracting the modules
    for match in matches:
        match_str = match.decode('utf-8')
        decoded_str = base64.b64decode(match_str)
            
        if b'DW' in decoded_str:
            found_match_loader = True
            data_dict = json.loads(decoded_str)
            for elem in data_dict:
                if elem['Method'] == 'DW':
                    print("Loader module found:", elem)
            print("Loader module offset:", hex(data.find(match)))

        if b'PS' in decoded_str:
            found_match_PowerShell = True
            data_dict = json.loads(decoded_str)
            for elem in data_dict:
                if elem['Method'] == 'PS':
                    print("PowerShell module found:", elem)
            print("PowerShell module offset:", hex(data.find(match)))

        if b'Path' in decoded_str:
            found_match_grabber = True
            grabber_found = True
            break
        else:
            grabber_match = re.search(b'W3siUGF0aCI6.{116}', data)
            if grabber_match:
                found_match_grabber = True
                encoded_string = grabber_match.group(0)
                decoded_str = base64.b64decode(encoded_string)
                grabber_str = decoded_str[:95].decode('utf-8', errors='ignore')
                cleanup_str = grabber_str.split('[')[-1].split(']')[0]
                
                if not grabber_found:
                    grabber_found = True
                    print("Grabber module found:", cleanup_str)
                    print("Graber module offset:", hex(data.find(encoded_string)))


    if not found_match_config:
        print("No configurartion found")
    if not found_match_loader:
        print("No Loader module found")
    if not found_match_PowerShell:
        print("No PowerShell module found")
    if not found_match_grabber:
        print("No Grabber module found")

    # Extract the C2
    matches = re.findall(pattern_c2, data)

    if matches:
        last_match = matches[-1]
        offset = data.find(last_match)
        print(f"C2 found at: {last_match.decode('utf-8')} at offset {hex(offset)}")
    else:
        print("No C2 found")
