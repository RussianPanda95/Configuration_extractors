# Author RussianPanda
# Date: 2021-09-26

import struct

def xtea_decrypt(v, k):
    v0, v1 = v[0], v[1]
    sum = 0xC6EF3720
    delta = 0x9E3779B9

    for _ in range(32):
        v1 = (v1 - (((((v0 << 4) & 0xFFFFFFFF) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]))) & 0xFFFFFFFF
        sum = (sum - delta) & 0xFFFFFFFF
        v0 = (v0 - (((((v1 << 4) & 0xFFFFFFFF) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]))) & 0xFFFFFFFF

    return [v0, v1]

encrypted_data = "" # encrypted data in hex
key_h = "" # key in hex

key_bytes = bytes.fromhex(key_h)

key = [struct.unpack('<I', key_bytes[i*4:(i+1)*4])[0] for i in range(4)]

print("Key values:")
for i in range(4):
    print(f"Key[{i}]: 0x{key[i]:08X}")

encrypted_bytes = bytes.fromhex(encrypted_data)

decrypted_data = bytearray()

for i in range(0, len(encrypted_bytes), 8):
    block = encrypted_bytes[i:i+8]
    v = [
        struct.unpack('<I', block[0:4])[0],
        struct.unpack('<I', block[4:8])[0]
    ]
    decrypted_block = xtea_decrypt(v, key)
    decrypted_data.extend(struct.pack('<II', *decrypted_block))

print("\nDecrypted data (hex):")
print(decrypted_data.hex().upper())

with open('decrypted.bin', 'wb') as f:
    f.write(decrypted_data)
    print("Decrypted data written to 'decrypted.bin'.")
