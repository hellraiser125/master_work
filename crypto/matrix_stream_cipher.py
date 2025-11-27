from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple, Dict, Optional, Any
import base64
import secrets

from helpers.salt import generate_salt  # returns base64 string with random bytes

P       = 65537
MASK16  = (1 << 16) - 1
MASK64  = (1 << 64) - 1

# 64-bit feedback polynomial (maximal LFSR)
LFSR_POLY_64 = 0x800000000000000D


# ---------------- basic packing ----------------

def pack_M0_from_text(msg_utf8: bytes) -> Tuple[List[List[int]], bytes, bytes]:
    """
    Take first 18 bytes (zero-extend to 18 if short) and map to a 3x3 matrix
    of 16-bit little-endian words modulo P.

    Returns:
        M0_matrix (3x3 ints mod P),
        rest_bytes (bytes after the first 18),
        m0_bytes_18 (exact 18-byte buffer we used)
    """
    first = msg_utf8[:18]
    if len(first) < 18:
        first = first + b"\x00" * (18 - len(first))
    rest = msg_utf8[18:]

    words = [int.from_bytes(first[i:i+2], "little") % P for i in range(0, 18, 2)]
    M0 = [
        [words[0], words[1], words[2]],
        [words[3], words[4], words[5]],
        [words[6], words[7], words[8]],
    ]
    return M0, rest, first  # first is exactly 18 bytes


def unpack_M0_to_bytes(M0: List[List[int]]) -> bytes:
    """
    Inverse of pack_M0_from_text for exactly 18 bytes (no trimming).
    """
    out = bytearray()
    flat = (
        M0[0][0], M0[0][1], M0[0][2],
        M0[1][0], M0[1][1], M0[1][2],
        M0[2][0], M0[2][1], M0[2][2],
    )
    for v in flat:
        x = v % P
        if x == 65536:
            x = 0
        out += (x & 0xFFFF).to_bytes(2, "little")
    return bytes(out)  # 18 bytes


def pack_u64_stream_no_pad(data: bytes) -> List[int]:
    """
    Split bytes into 64-bit LE words WITHOUT adding an extra block.
    The last chunk (<8B) is zero-extended inside the word.
    """
    if not data:
        return []
    res: List[int] = []
    for i in range(0, len(data), 8):
        chunk = data[i:i+8]
        if len(chunk) < 8:
            chunk += b"\x00" * (8 - len(chunk))
        res.append(int.from_bytes(chunk, "little"))
    return res


def unpack_u64_stream_to_bytes(words: List[int]) -> bytes:
    return b"".join(int(w & MASK64).to_bytes(8, "little") for w in words)


# ---------------- 3x3 matrix mod P ----------------

def matmul3(A: List[List[int]], B: List[List[int]]) -> List[List[int]]:
    C = [[0, 0, 0], [0, 0, 0], [0, 0, 0]]
    for i in range(3):
        for j in range(3):
            s = 0
            for k in range(3):
                s = (s + (A[i][k] % P) * (B[k][j] % P)) % P
            C[i][j] = s
    return C


def transpose3(A: List[List[int]]) -> List[List[int]]:
    return [[A[j][i] % P for j in range(3)] for i in range(3)]


# ---------------- gamma core (f64 and LFSR) ----------------

def _mul128(x: int, y: int) -> Tuple[int, int]:
    """
    128-bit product of two 64-bit integers, returned as (hi, lo).
    """
    prod = (x & MASK64) * (y & MASK64)
    lo = prod & MASK64
    hi = (prod >> 64) & MASK64
    return hi, lo


def _f64(x: int, g_prev: int) -> int:
    """
    Legacy 2-argument f64 used in key compression.
    f64(x, g) = (hi128(x*g) + lo128(x*g)) mod 2^64
    """
    hi, lo = _mul128(x, g_prev)
    return (hi + lo) & MASK64


def _f64_triple(m_word: int, g_prev: int, f_prev: int) -> int:
    """
    3-argument variant for the stream cipher:
        g_i = f64(M_{i-1}, g_{i-1}, F_{i-1})
            = ((M_{i-1} * g_{i-1} * F_{i-1})_L
               + (M_{i-1} * g_{i-1} * F_{i-1})_R) mod 2^64
    where (_L, _R) are the high/low 64 bits of the 128 low bits of the product.
    """
    prod = (m_word & MASK64) * (g_prev & MASK64) * (f_prev & MASK64)
    lo = prod & MASK64
    hi = (prod >> 64) & MASK64
    return (hi + lo) & MASK64


def lfsr_step(state: int) -> int:
    """
    One step of 64-bit LFSR with feedback polynomial LFSR_POLY_64.
    Zero state is mapped to 1 to avoid lock-up.
    """
    state &= MASK64
    if state == 0:
        state = 1
    lsb = state & 1
    state >>= 1
    if lsb:
        state ^= LFSR_POLY_64
    return state & MASK64


def g_next(x: int, g_prev: int) -> int:
    """
    Backwards-compatible alias for the legacy 2-argument gamma update.
    """
    return _f64(x, g_prev)


# ---------------- K(1024) -> K0(64) ----------------

def _split_4x256(K: int) -> Tuple[int, int, int, int]:
    b = K.to_bytes(128, "big")
    return tuple(int.from_bytes(b[i*32:(i+1)*32], "big") for i in range(4))


def _fold256_to_64(x: int) -> int:
    b = x.to_bytes(32, "big")
    limbs = [int.from_bytes(b[i*8:(i+1)*8], "big") for i in range(4)]
    return (limbs[0] + limbs[1] + limbs[2] + limbs[3]) & MASK64


def compress_1024_to_64(K: int) -> int:
    a1, a2, a3, a4 = _split_4x256(K)
    b1, b2, b3, b4 = map(_fold256_to_64, (a1, a2, a3, a4))
    s1, s2 = _f64(b1, b2), _f64(b3, b4)
    return _f64(s1, s2)


def generate_random_1024() -> int:
    K = secrets.randbits(1024)
    K |= (1 << 1023)
    return K


# ---------------- K0 -> quaternion words; normalize q̂; Gamma(q̂) ----------------

def k0_to_quaternion_words(k0: int) -> Tuple[int, int, int, int]:
    w =  k0        & 0xFFFF
    x = (k0 >> 16) & 0xFFFF
    y = (k0 >> 32) & 0xFFFF
    z = (k0 >> 48) & 0xFFFF
    return w % P, x % P, y % P, z % P


def _legendre_symbol(a: int, p: int = P) -> int:
    a %= p
    if a == 0:
        return 0
    r = pow(a, (p - 1) // 2, p)
    return -1 if r == p - 1 else r


def _modinv(a: int, p: int = P) -> int:
    return pow(a % p, p - 2, p)


def _tonelli_shanks(n: int, p: int = P) -> Optional[int]:
    n %= p
    if n == 0:
        return 0
    if _legendre_symbol(n, p) != 1:
        return None
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while _legendre_symbol(z, p) != -1:
        z += 1
    m = s
    c = pow(z, q, p)
    t = pow(n, q, p)
    r = pow(n, (q + 1) // 2, p)
    while t != 1:
        i = 1
        t2i = (t * t) % p
        while i < m and t2i != 1:
            t2i = (t2i * t2i) % p
            i += 1
        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = (b * b) % p
        t = (t * c) % p
        r = (r * b) % p
    return r


def normalize_quaternion_from_k0(k0: int):
    """
    Find delta on z so that N = w^2+x^2+y^2+z^2 (mod P) is a quadratic residue,
    then q̂ = t*(w,x,y,z) (mod P) with t^2 ≡ N^{-1} (mod P) (choose smaller t).
    Returns: ŵ,x̂,ŷ,ẑ,t,delta,N_before,debug_dict
    """
    w, x, y, z0 = k0_to_quaternion_words(k0)
    attempts = []
    delta = 0
    while True:
        z = (z0 + delta) % P
        N = (w*w + x*x + y*y + z*z) % P
        ls = _legendre_symbol(N, P)
        attempts.append({"delta": delta, "z": z, "N": N, "legendre": ls})
        if ls == 1:
            invN = _modinv(N, P)
            t_candidate = _tonelli_shanks(invN, P)
            if t_candidate is None:
                delta += 1
                continue
            t_alt = (P - t_candidate) % P
            t = min(t_candidate, t_alt)
            w_hat = (t * w) % P
            x_hat = (t * x) % P
            y_hat = (t * y) % P
            z_hat = (t * z) % P
            N_hat = (w_hat*w_hat + x_hat*x_hat + y_hat*y_hat + z_hat*z_hat) % P
            debug = {
                "wxyz_raw": (w, x, y, z0),
                "attempts": attempts,
                "chosen": {
                    "delta": delta,
                    "z": z,
                    "N": N,
                    "invN": invN,
                    "t": t,
                    "q_hat": (w_hat, x_hat, y_hat, z_hat),
                    "norm_after": N_hat,
                },
            }
            return w_hat, x_hat, y_hat, z_hat, t, delta, N, debug
        delta += 1


def gamma_from_quaternion(w: int, x: int, y: int, z: int) -> List[List[int]]:
    md = lambda v: v % P
    r11 = md(1 - 2*(y*y + z*z)); r12 = md(2*(x*y - w*z)); r13 = md(2*(x*z + w*y))
    r21 = md(2*(x*y + w*z));     r22 = md(1 - 2*(x*x + z*z)); r23 = md(2*(y*z - w*x))
    r31 = md(2*(x*z - w*y));     r32 = md(2*(y*z + w*x));     r33 = md(1 - 2*(x*x + y*y))
    return [[r11, r12, r13], [r21, r22, r23], [r31, r32, r33]]


# ---------------- gamma over M0 then rest (no padding) ----------------

def m0_words_no_pad(m0_bytes_18: bytes) -> List[int]:
    """
    Map 18 bytes of M0 into three 64-bit LE words WITHOUT padding blocks.
    The last 2 bytes are zero-extended to 8 bytes.
    """
    assert len(m0_bytes_18) == 18
    w0 = int.from_bytes(m0_bytes_18[0:8],  "little")
    w1 = int.from_bytes(m0_bytes_18[8:16], "little")
    w2 = int.from_bytes(m0_bytes_18[16:18] + b"\x00"*6, "little")
    return [w0, w1, w2]


def _salt64_from_b64(salt_b64: str) -> int:
    raw = base64.b64decode(salt_b64.encode("utf-8"), validate=True)
    if len(raw) < 8:
        raw += secrets.token_bytes(8 - len(raw))
    return int.from_bytes(raw[:8], "little") or 1


def gamma_chain_no_pad(
    K0: int,
    m0_bytes_18: bytes,
    rest_bytes: bytes,
    salt_b64: Optional[str],
) -> Tuple[int, List[int]]:
    """
    Gamma chain used for MAC computation.

    g0 = K0, F0 is derived from K0 by the first LFSR step.
    For each 64-bit word X (first words of M0, then words of the rest):
        1) F <- LFSR(F)
        2) g <- f64_triple(X, g, F)
        3) if g == 0 and salt is provided, add salt modulo 2^64.

    Returns: (g_final, g_trace) where g_trace[0] = g0, g_trace[i] = g_i.
    """
    words = m0_words_no_pad(m0_bytes_18) + pack_u64_stream_no_pad(rest_bytes)
    salt64 = _salt64_from_b64(salt_b64) if salt_b64 else 0

    g = K0 & MASK64
    f_state = K0 & MASK64
    trace = [g]

    for x in words:
        f_state = lfsr_step(f_state)
        g = _f64_triple(x & MASK64, g, f_state)
        if g == 0 and salt64:
            g = (g + salt64) & MASK64
        trace.append(g)

    return g, trace


# ---------------- ciphertext container ----------------

@dataclass
class Ciphertext:
    C0: List[List[int]]           # 3x3 matrix mod P
    stream: List[int]             # 64-bit ciphertext blocks for the "rest"
    mac: int                      # 64-bit MAC (final g)
    meta: Dict[str, Any]          # length, k0, salt, etc.


# ---------------- high-level encrypt / decrypt ----------------

def encrypt(text: str, K0: int, Gamma: List[List[int]]) -> Ciphertext:
    """
    One-shot encryption with NO padding in gamma.

    Steps:
      • Build M0 (zero-extend to 18) and C0 = Gamma · M0 (mod P).
      • MAC chain: g0 = K0, LFSR seeded from K0; process M0 words, then rest.
      • Stream XOR only for the *rest*:
            C_i = X_i XOR g_{i-1},
        where g_{i-1} evolves via f64(M, g, F) with F generated by LFSR.
      • MAC = final g of the MAC chain.
    """
    msg = text.encode("utf-8")
    M0, rest, m0_bytes_18 = pack_M0_from_text(msg)
    C0 = matmul3(Gamma, M0)

    mac_salt_b64 = generate_salt(8)
    g_final, g_trace = gamma_chain_no_pad(K0, m0_bytes_18, rest, mac_salt_b64)

    # Stream encrypt the "rest" starting from g after the three M0 words
    g_prev = g_trace[3] if len(g_trace) >= 4 else g_trace[-1]
    X_words = pack_u64_stream_no_pad(rest)

    # LFSR state after processing the three M0 words (same for enc/dec)
    f_state = K0 & MASK64
    for _ in range(len(m0_words_no_pad(m0_bytes_18))):
        f_state = lfsr_step(f_state)

    C_stream: List[int] = []
    for x in X_words:
        C_stream.append((x ^ g_prev) & MASK64)
        f_state = lfsr_step(f_state)
        g_prev = _f64_triple(x & MASK64, g_prev, f_state)

    return Ciphertext(
        C0=C0,
        stream=C_stream,
        mac=int(g_final & MASK64),
        meta={
            "len": len(msg),
            "k0": int(K0 & MASK64),
            "mac_mode": "no_pad_all",
            "mac_salt_b64": mac_salt_b64,
        },
    )


def decrypt(ct: Ciphertext, K0: int, Gamma: List[List[int]]) -> str:
    """
    Decrypt and verify MAC according to the same no-pad rules.
    """
    # Recover M0 (18 bytes) from C0
    M0_dec = matmul3(transpose3(Gamma), ct.C0)  # Γ^{-1} = Γ^T (orthogonal)
    m0_bytes_18 = unpack_M0_to_bytes(M0_dec)

    # Starting gamma after M0 for stream decryption
    salt_b64 = ct.meta.get("mac_salt_b64") or None
    g_after_m0, trace_m0 = gamma_chain_no_pad(K0, m0_bytes_18, b"", salt_b64)
    g_prev = trace_m0[-1]

    # LFSR state after processing three M0 words (same as in encrypt)
    f_state = K0 & MASK64
    for _ in range(len(m0_words_no_pad(m0_bytes_18))):
        f_state = lfsr_step(f_state)

    X_dec: List[int] = []
    for c in ct.stream:
        c_int = int(c) & MASK64
        x = (c_int ^ g_prev) & MASK64
        X_dec.append(x)
        f_state = lfsr_step(f_state)
        g_prev = _f64_triple(x, g_prev, f_state)

    rest_bytes = unpack_u64_stream_to_bytes(X_dec)

    # Verify MAC: run full chain (M0 + rest)
    mac_check, _ = gamma_chain_no_pad(K0, m0_bytes_18, rest_bytes, salt_b64)
    if (mac_check & MASK64) != (ct.mac & MASK64):
        raise ValueError(f"MAC mismatch: calc={mac_check:#018x} vs recv={ct.mac:#018x}")

    full = m0_bytes_18 + rest_bytes
    return full[:int(ct.meta["len"])].decode("utf-8", errors="strict")


__all__ = [
    "P", "MASK16", "MASK64",
    "pack_M0_from_text", "unpack_M0_to_bytes",
    "pack_u64_stream_no_pad", "unpack_u64_stream_to_bytes",
    "matmul3", "transpose3",
    "_f64", "g_next", "lfsr_step",
    "m0_words_no_pad", "gamma_chain_no_pad",
    "generate_random_1024", "compress_1024_to_64",
    "k0_to_quaternion_words", "normalize_quaternion_from_k0", "gamma_from_quaternion",
    "Ciphertext",
    "encrypt", "decrypt",
]
