import os
import base64


def generate_salt(length: int = 16) -> str:
    salt_bytes = os.urandom(length)
    salt_b64 = base64.b64encode(salt_bytes).decode('utf-8')
    return salt_b64
