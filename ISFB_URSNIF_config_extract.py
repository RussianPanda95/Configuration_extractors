
import struct 
import malduck
import re

FILE_PATH = 'filename'

data = open(FILE_PATH, 'rb').read()


# decompressing aplib from the extracted blobs
jj_structure = []

for i in range(len(data)):
    if data[i:i+2] == b'JJ':
        jj_structure.append(data[i:i+20])
extracted_blob_one = data[43520:43520+511]
blob = malduck.aplib.decompress(extracted_blob_one)
convert_bytes_to_str = blob.decode(errors='replace')

# grabbing the C2 information
C2_table = []
matches = re.finditer(r'([-\w]+(\.[-\w]+)+)', convert_bytes_to_str)
for m in matches:
      C2_table.append(m.group(0))
del C2_table[0]

# grabbing wordlist 
extracted_blob_two = data[44032:44032+475]
blob_two = malduck.aplib.decompress(extracted_blob_two)
wordlist = blob_two.decode(errors='replace').strip('\r\n').split('\r\n')
print(wordlist)
del wordlist[0]

# extracting the blobs and outputting the results
for i in range(len(jj_structure)):
    xor_key = struct.unpack("<I", jj_structure[i][4:8])[0]
    print(f"XOR Key: {xor_key}")
    hash_offset = struct.unpack("<I", jj_structure[i][8:12])[0]
    hash_hex = hex(hash_offset)
    print(f"Hash: {hash_hex}")
    if hash_offset == 2410798561: 
        print(f"C2 Table: {C2_table} at offset " + hex(43520))
    if hash_offset == 1760278915: 
        print(f"WORDLIST: {wordlist} at offset " + hex(44032))
    

    blob_offset = struct.unpack("<I", jj_structure[i][12:16])[0] - 8704
    blob_size = struct.unpack("<I", jj_structure[i][16:20])[0]





