# Перетворення повідомлення -> кватернарний "хеш" -> 32-байтовий ключ AES
# Використовує QuaternionProcessor і reducer.reduce_data
import struct
from typing import Tuple, Optional, Union

from core.processor import QuaternionProcessor
from helpers.reducer import reduce_data

# імпорт цілочисельного кватерніону з вашого проекту
from core.quaternion import Quaternion as IntQuaternion


def message_to_chunk_dict(message: str, salt: Optional[str] = None) -> dict:
    """
    Перетворює message (str) і salt (str) у словник chunk'ів
    у форматі, який очікує QuaternionProcessor.
    """
    if salt is None:
        salt = ""
    data = (message + salt).encode('utf-8')
    i = 0
    chunk_number = 1
    chunk_dict = {}
    while i < len(data):
        chunk = data[i:i+8]
        if len(chunk) < 8:
            chunk += b'\0' * (8 - len(chunk))
        decimal_values = list(struct.unpack('B' * len(chunk), chunk))
        chunk_dict[chunk_number] = decimal_values
        chunk_number += 1
        i += 8
    return chunk_dict


# -------------------- ВЛАСНИЙ KDF (без SHA/HMAC) --------------------
def _int_to_bytes_be(x: int, nbytes: int) -> bytes:
    return int(x & ((1 << (8 * nbytes)) - 1)).to_bytes(nbytes, 'big', signed=False)


def _rotate_bytes_left(b: bytearray, k: int) -> bytearray:
    if len(b) == 0:
        return b
    k = k % len(b)
    return b[k:] + b[:k]


def derive_key_custom(root: Union[IntQuaternion, Tuple[int, int, int, int]],
                      salt: str,
                      rounds: int = 12,
                      out_len: int = 32) -> bytes:
    """
    Власний KDF на основі ітеративного "змішування" кватерніонів і солі.
    Повертає out_len байтів.
    - root: IntQuaternion або кортеж 4 int
    - salt: рядок (включається в мікшування)
    """
    # Привести root до IntQuaternion
    if isinstance(root, IntQuaternion):
        mix = IntQuaternion(int(root.a), int(root.b), int(root.c), int(root.d))
    else:
        mix = IntQuaternion(int(root[0]), int(root[1]), int(root[2]), int(root[3]))

    # Якщо root тривіальний (усі нулі), використаємо невелику non-zero заміну для KDF (щоб не отримати нульовий ключ)
    if (mix.a | mix.b | mix.c | mix.d) == 0:
        mix = IntQuaternion(0x0102030405060708, 0x1122334455667788, 0x99AABBCCDDEEFF00, 0x0F1E2D3C4B5A6978)

    # Константи раундів (фіксовані; задокументуйте у роботі)
    ROUND_CONSTS = [
        (0x243F6A8885A308D3, 0x13198A2E03707344, 0xA4093822299F31D0, 0x082EFA98EC4E6C89),
        (0x452821E638D01377, 0xBE5466CF34E90C6C, 0xC0AC29B7C97C50DD, 0x3F84D5B5B5470917),
        (0x9216D5D98979FB1B, 0xD1310BA698DFB5AC, 0x2FFD72DBD01ADFB7, 0xB8E1AFED6A267E96),
    ]

    consts = []
    for i in range(rounds):
        c = ROUND_CONSTS[i % len(ROUND_CONSTS)]
        consts.append((c[0] ^ i, c[1] ^ (i << 1), c[2] ^ (i << 2), c[3] ^ (i << 3)))

    # salt -> байти, підготувати до XOR (повторюємо/обрізуємо до 32 байт)
    saltb = (salt or "").encode('utf-8')
    if len(saltb) == 0:
        # невеликий non-zero salt, якщо передано пусту рядок
        saltb = b'\x55' * 16
    saltb = (saltb * ((32 // len(saltb)) + 1))[:32]

    mask64 = (1 << 64) - 1

    # Мікшувальні раунди
    for i in range(rounds):
        ca, cb, cc, cd = consts[i]
        qc = IntQuaternion(ca & mask64, cb & mask64, cc & mask64, cd & mask64)
        prod1 = mix * qc
        prod2 = qc * mix
        # компонентна комбінація (додавання мод 2**64)
        new_a = (int(prod1.a) + int(prod2.a)) & mask64
        new_b = (int(prod1.b) + int(prod2.b)) & mask64
        new_c = (int(prod1.c) + int(prod2.c)) & mask64
        new_d = (int(prod1.d) + int(prod2.d)) & mask64
        mix = IntQuaternion(new_a, new_b, new_c, new_d)
        # інкорпоруємо частинку salt (8-байтний чанк)
        start = (i * 8) % len(saltb)
        chunk = saltb[start:start + 8]
        if len(chunk) < 8:
            chunk = (chunk + b'\x00' * 8)[:8]
        sval = int.from_bytes(chunk, 'big')
        mix = IntQuaternion(mix.a ^ sval,
                            mix.b ^ ((sval << 1) & mask64),
                            mix.c ^ ((sval << 2) & mask64),
                            mix.d ^ ((sval << 3) & mask64))

    # Серіалізація компонентів в 32 байти (big-endian)
    out = b''.join(_int_to_bytes_be(x & mask64, 8) for x in (mix.a, mix.b, mix.c, mix.d))

    # Фінальна дифузія: ротація байтів і XOR із salt
    ba = bytearray(out)
    rotate_by = (int(mix.a) ^ int(mix.b)) & 31  # 0..31
    ba = _rotate_bytes_left(ba, rotate_by)
    for i in range(len(ba)):
        ba[i] ^= saltb[i % len(saltb)]

    # Повертаємо перші out_len байтів
    return bytes(ba[:out_len])


# -------------------- Основна функція --------------------
def compute_quaternion_key_from_message(message: str, salt: str) -> Tuple[bytes, 'IntQuaternion']:
    """
    Повертає (key_bytes, root_quaternion_object).
    key_bytes — 32 байти (AES-256).
    root_quaternion_object — сам Quaternion (a,b,c,d).
    """
    chunks = message_to_chunk_dict(message, salt)
    processor = QuaternionProcessor(chunks)
    quaternions = processor.make_quaternion()
    tree = reduce_data(quaternions)
    if tree and tree[-1]:
        root = tree[-1][0]
    else:
        # якщо немає результату — повертаємо нуль-куатерніон (як раніше)
        root = IntQuaternion(0, 0, 0, 0)

    # Використовуємо власний KDF (без SHA) для вироблення 32 байт ключа
    key_bytes = derive_key_custom(root, salt, rounds=12, out_len=32)

    return key_bytes, root
