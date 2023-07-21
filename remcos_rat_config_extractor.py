# Author: RussianPanda
# Reference: https://perception-point.io/blog/behind-the-attack-remcos-rat/
# Tested on samples:
# 536d16dd4765a7637cd37859010639c1fe776598f3c9c97cb3ea41e2ad2d6d6b
# 94a4e5c7a3524175c0306c5748c719a940a7bfbe778c5a16627193a684fa10f0
# 8b6a909110ca907eb279cfb8f6db432af5564263e49c6982001b83fcffe04c07*

import pefile
import string
import re 
import argparse

def rc4_decrypt(key, encrypted_data):
    S = list(range(256))
    j = 0
    out = []

    # KSA 
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # PRGA 
    i = j = 0
    for byte in encrypted_data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])

    return bytes(out)

def remove_junk_sym(data):
    printable = set(bytes(string.printable, 'ascii'))

    return bytes(filter(printable.__contains__, data))

def extract_resources(file_path):
    pe = pefile.PE(file_path)
    decrypted_data_to_str = ''

    for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if resource.struct.Id == 10:  # 10 is the type id for RCDATA
            for resource_id in resource.directory.entries:
                data_rva = resource_id.directory.entries[0].data.struct.OffsetToData
                size = resource_id.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                key_size = data[0]  
                key = data[1:key_size+1]  
                encrypted_data = data[key_size+1:]
                decrypt_data = rc4_decrypt(key, encrypted_data)
                decrypted_data = remove_junk_sym(decrypt_data[:510])
                decrypted_data_to_str = decrypted_data.decode("utf-8")  
                
    return decrypted_data_to_str

parser = argparse.ArgumentParser(description="Extract Remcos RAT configuration.")
parser.add_argument("file", help="Path to the file to decrypt")
args = parser.parse_args()

decrypted_data = extract_resources(args.file) 
C2 = re.match("^(.*?):1", decrypted_data)  

if C2:
    print(f"C2: {C2.group(1)}") 
else:
    print("No C2 found")

AssignedName = re.search(":1\|\|(.*?)\|\|", decrypted_data)

if AssignedName:
    print(f"Assigned Name: {AssignedName.group(1)}")  
else:
    print("No Assigned Name found")

FileCopy = re.search("(\w+\.exe)", decrypted_data)


if FileCopy:
    print(f"File Copy: {FileCopy.group()}") 
else:
    print("No File Copy found")

decrypted_data_list = decrypted_data.split('||')  # split on '||'
try:
    mic_index = decrypted_data_list.index('MicRecords')  # get the index of 'MicRecords'
except ValueError:
    print("MicRecords not found in decrypted data.")
else:
    # iterate over the items after 'MicRecords'
    for item in decrypted_data_list[mic_index+1:]:
        if item and item != '0' and item and item != '1':  # if the element is not an empty string and not '0' and not '1'
            print(f'File Copy Folder: {item}')
            break
try:
    file_copy_index = decrypted_data_list.index(FileCopy.group(1))  # get the index of 'FileCopy'
except ValueError:
    print("FileCopy not found in decrypted data.")
else:
    # iterate over the items after 'FileCopy'
    for item in decrypted_data_list[file_copy_index+1:]:
        if item and item != '0' and item != '1':  # if the item is not an empty string and not '0' and not '1'
            print(f'Startup Name: {item}')
            break

mutex = re.search("[a-zA-Z0-9]+-[a-zA-Z0-9]+", decrypted_data)
if mutex:
    print(f"Mutex: {mutex.group()}") 
else:
    print("No Mutex found")

