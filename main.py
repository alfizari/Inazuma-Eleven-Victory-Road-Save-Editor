import tkinter as tk
from tkinter import filedialog, messagebox
import os, struct, binascii
import numpy as np
from numba import njit


CRC32_TABLE = [0] * 256
for i in range(256):
    c = i
    for _ in range(8):
        if c & 1:
            c = 0xEDB88320 ^ (c >> 1)
        else:
            c >>= 1
    CRC32_TABLE[i] = c


@njit(cache=True)
def decrypt_data_fast_numba(data, key, offset, table):
    result = data.copy()
    crc = 0
    k0 = (key >> 0) & 0xFF
    k1 = (key >> 8) & 0xFF
    k2 = (key >> 16) & 0xFF
    k3 = (key >> 24) & 0xFF
    n = result.shape[0]

    for i in range(n):
        index = (i + offset) & 0xFFFFFFFF

        if (index & 3) == 0:
            eax = (~index) & 0xFFFFFFFF
            eax = (eax >> 8) ^ table[(eax & 0xFF) ^ k0]
            eax = (eax >> 8) ^ table[(eax & 0xFF) ^ k1]
            eax = (eax >> 8) ^ table[(eax & 0xFF) ^ k2]
            eax = (eax >> 8) ^ table[(eax & 0xFF) ^ k3]
            crc = (~eax) & 0xFFFFFFFF

        pos = index & 3
        r10 = pos << 1
        ks =  (crc >> r10) & 0x03
        ks = (ks << 2) | ((crc >> (r10 + 8)) & 0x03)
        ks = (ks << 2) | ((crc >> (r10 + 16)) & 0x03)
        ks = (ks << 2) | ((crc >> (r10 + 24)) & 0x03)
        result[i] ^= ks

    return result

def process_file(path, data):


    filename = os.path.basename(path)
    key = binascii.crc32(filename.encode("ascii")) & 0xFFFFFFFF
    MAGIC = 0x9DCE66C3

    STATE = ''
    if filename.endswith('USERDATALIVE'):
        magic = struct.unpack_from("<I", data, 0x00)[0]
        STATE = "encrypting" if magic == MAGIC else "decrypting"

    if STATE == "encrypting":
        # Autosave hash
        autosave_size = struct.unpack_from("<I", data, 0x54)[0]
        autosave_region = data[0x800:0x800+autosave_size]
        autosave_crc = binascii.crc32(autosave_region) & 0xFFFFFFFF
        struct.pack_into("<I", data, 0x50, autosave_crc)

        # Headersave hash
        headersave_start = 0x800 + autosave_size
        headersave_crc = binascii.crc32(data[headersave_start:]) & 0xFFFFFFFF
        struct.pack_into("<I", data, 0xD0, headersave_crc)

        # File header hash
        crc_region = data[0x08:0x800]
        crc = binascii.crc32(crc_region) & 0xFFFFFFFF
        struct.pack_into("<I", data, 0x04, crc)

    # Convert to NumPy for Numba
    data_np = np.frombuffer(bytes(data), dtype=np.uint8)
    crc_table_np = np.array(CRC32_TABLE, dtype=np.uint32)

    # Decrypt/encrypt
    out_np = decrypt_data_fast_numba(data_np, key, 0, crc_table_np)

    data_bytes = out_np.tobytes()

    #with open(path, "wb") as f:
        #f.write(out_np.tobytes())
    return bytearray(data_bytes)


