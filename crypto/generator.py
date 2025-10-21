# generator_quat_compress.py
"""
Compress 1024-bit key -> 64-bit via quaternion multiplications.

Algorithm:
1) Split 1024-bit integer K into 4 x 256-bit parts (A,B,C,D) (big-endian).
2) For each 256-bit part, split into 4 x 64-bit limbs -> Quaternion( limb0, limb1, limb2, limb3 ).
3) h = A_quat * B_quat
   j = C_quat * D_quat
   r = h * j
4) K0 = (r.a + r.b + r.c + r.d) mod 2^64
"""
from typing import Tuple
import secrets
import hashlib
import math
import random

MASK64 = (1 << 64) - 1

# --- helper: split 1024 -> 4 x 256 (big-endian) ---
def split_1024_to_4x256(K: int) -> Tuple[int, int, int, int]:
    if K.bit_length() > 1024:
        raise ValueError("K must be at most 1024 bits")
    b = K.to_bytes(128, "big")  # 128 bytes = 1024 bits
    parts = tuple(int.from_bytes(b[i*32:(i+1)*32], "big") for i in range(4))
    return parts

# --- helper: split 256 -> 4 x 64 (big-endian) ---
def split_256_to_4x64(x256: int) -> Tuple[int, int, int, int]:
    b = x256.to_bytes(32, "big")  # 32 bytes = 256 bits
    limbs = tuple(int.from_bytes(b[i*8:(i+1)*8], "big") for i in range(4))
    return limbs

# If you keep quaternion.py in the same package, import it:
# from .quaternion import Quaternion
# For standalone test, we assume Quaternion class from your repo is importable.
from core.quaternion import Quaternion  # adjust import path if needed

def compress_1024_to_64_via_quaternions(K: int) -> int:
    """
    Compress 1024-bit integer K into 64-bit integer using quaternion path described above.
    Returns integer in range [0, 2^64-1].
    """
    a256, b256, c256, d256 = split_1024_to_4x256(K)

    # build quaternions from 256-bit parts (each -> 4 x 64-bit limbs)
    A = Quaternion(*split_256_to_4x64(a256))
    B = Quaternion(*split_256_to_4x64(b256))
    C = Quaternion(*split_256_to_4x64(c256))
    D = Quaternion(*split_256_to_4x64(d256))

    # quaternion multiplications (uses Quaternion.__mul__)
    h = A * B
    j = C * D
    r = h * j

    # final 64-bit key: sum components modulo 2^64
    K0 = ( (r.a & MASK64) + (r.b & MASK64) + (r.c & MASK64) + (r.d & MASK64) ) & MASK64
    return K0

# ---------------------------
# --- Replacement section: use provided DH code to obtain key source
# ---------------------------

class PrimeAndGenerator:
    """ prime and generator for Diffie-Hellman Algorithm """

    @staticmethod
    def is_prime(num: int) -> bool:
        """ brute-force determine if a number is prime """
        if num <= 1:
            return False
        for i in range(2, int(math.isqrt(num)) + 1):
            if num % i == 0:
                return False
        return True

    def __init__(self):
        """ initialize by creating the prime and the generator
            using smallish numbers because this is just a demo
            real implementations use at least 2048 bit numbers """
        self.generator = random.randint(10000, 100000)
        self.prime = random.randint(1_000_000_000, 4_000_000_000)
        while not PrimeAndGenerator.is_prime(self.prime):
            self.prime = random.randint(1_000_000_000, 4_000_000_000)

    def get_prime(self) -> int:
        """ return the large prime number"""
        return self.prime

    def get_generator(self) -> int:
        """ return the generator """
        return self.generator


class DHParticipant:
    """ a pair of participants make up the Diffie-Hellman key exchange """

    def __init__(self, png: PrimeAndGenerator):
        """ init the participant, generating public and private key """
        self.png = png
        # small private for demo; if you want larger private keys, increase range
        self._private_key = random.randint(1_000, 65_535)
        # use pow with modulus
        self.public_key = pow(self.png.get_generator(), self._private_key, self.png.get_prime())

        self.other_public = 0
        self.shared_secret = 0

    def get_public_key(self) -> int:
        """ get the public key property """
        return self.public_key

    def calc_shared_secret(self, other_public: int) -> int:
        """ calc the shared secret """
        self.other_public = other_public  # just saving
        self.shared_secret = pow(other_public, self._private_key, self.png.get_prime())
        return self.shared_secret

    def get_shared_secret(self) -> int:
        """ get the shared secret, if it exists """
        if self.shared_secret == 0:
            raise ValueError("shared secret has not been calculated")
        return self.shared_secret

def _derive_1024_from_int(x: int) -> int:
    """
    Deterministically expand integer x into a 1024-bit integer using SHA-512 in counter mode.
    Returns integer with the top bit (bit 1023) set to ensure 1024-bit length.
    """
    # convert x to minimal bytes
    x_bytes = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    out = b""
    # need 128 bytes (1024 bits) -> two SHA-512 outputs (2 * 64 = 128)
    for ctr in range(2):
        out += hashlib.sha512(x_bytes + ctr.to_bytes(1, "big")).digest()
    K = int.from_bytes(out[:128], "big")
    # ensure 1024-bit (set highest bit)
    K |= (1 << 1023)
    return K

def generate_random_1024_key() -> int:
    """
    Uses the provided Diffie-Hellman demonstration code to derive a key source,
    then expands that source deterministically into a 1024-bit integer for
    subsequent quaternion compression.
    No console output is produced.
    """
    pg = PrimeAndGenerator()
    alice = DHParticipant(pg)
    bob = DHParticipant(pg)

    # compute shared secret on both sides (no prints)
    alice.calc_shared_secret(bob.get_public_key())
    bob.calc_shared_secret(alice.get_public_key())

    # use alice's shared secret (they should match)
    shared = alice.get_shared_secret()

    # derive full 1024-bit key deterministically
    K = _derive_1024_from_int(shared)
    return K

# --- convenience: keep an alternative random generator if needed ---
def generate_random_1024_key_fallback() -> int:
    """original-style random 1024-bit fallback (kept for compatibility)"""
    K = secrets.randbits(1024)
    K |= (1 << 1023)  # ensure 1024-bit
    return K

# Example usage (kept under __main__ guard if you want to test locally)
if __name__ == "__main__":
    # no prints per your request; this block can be used for quick debugging if needed
    K = generate_random_1024_key()
    K0 = compress_1024_to_64_via_quaternions(K)
    # if you need to inspect values during debugging, add prints here locally
