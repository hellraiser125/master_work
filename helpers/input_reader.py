import struct
import os
import base64
from .salt import generate_salt


def read_chunks_from_console():
    chunk_dict = {}
    chunk_number = 1
    user_input = input("Enter your message: ") + generate_salt()
    byte_data = user_input.encode('utf-8')

    i = 0
    while i < len(byte_data):
        chunk = byte_data[i:i+8]
        if len(chunk) < 8:
            chunk += b'\0' * (8 - len(chunk))
        decimal_values = list(struct.unpack('B' * len(chunk), chunk))
        chunk_dict[chunk_number] = decimal_values
        chunk_number += 1
        i += 8

    return chunk_dict
