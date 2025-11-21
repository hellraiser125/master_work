from crypto.matrix_stream_cipher import (
    generate_random_1024,
    compress_1024_to_64,
    normalize_quaternion_from_k0,
    gamma_from_quaternion,
    encrypt,
)

def generate_nist_sequence(
    outfile: str = "nist_input.bin",
    num_sequences: int = 10,
    msg_len_bytes: int = 200_000,
):
    """
    num_sequences  – скільки різних послідовностей (різні ключі).
    msg_len_bytes  – довжина нульового plaintext'у в байтах.

    Вихід: один файл outfile з num_sequences послідовностей,
    записаних підряд у вигляді '0'/'1'.
    """
    total_bits = 0
    bits_per_sequence = None

    with open(outfile, "w", encoding="ascii") as f:
        for seq_idx in range(num_sequences):
            # 1) Генеруємо 1024-бітний K і стискаємо до 64-бітного K0
            K = generate_random_1024()
            K0 = compress_1024_to_64(K)

            # 2) Нормування → кватерніон → матриця Gamma
            w, x, y, z, t, delta, N, dbg = normalize_quaternion_from_k0(K0)
            Gamma = gamma_from_quaternion(w, x, y, z)

            # 3) Нульовий plaintext
            pt = "\x00" * msg_len_bytes

            # 4) Шифруємо
            ct = encrypt(pt, K0, Gamma)

            # Беремо лише потокову частину (ct.stream)
            words = ct.stream
            if bits_per_sequence is None:
                bits_per_sequence = len(words) * 64
            else:
                assert bits_per_sequence == len(words) * 64, "Різні довжини послідовностей"

            # 5) Пишемо 64-бітні слова як '0'/'1'
            for w64 in words:
                bits = f"{int(w64) & ((1 << 64) - 1):064b}"
                f.write(bits)
                total_bits += 64

            print(f"Готово послідовність #{seq_idx+1}")

    print()
    print(f"Файл       : {outfile}")
    print(f"К-сть seq  : {num_sequences}")
    print(f"Біт на seq : {bits_per_sequence}")
    print(f"Всього біт : {total_bits}")
    print()
    print("ЦІ ЧИСЛА потрібні будуть у NIST STS:")
    print("  - sequenceLength (довжина одного потоку)  -> Біт на seq")
    print("  - number of bitstreams                   -> К-сть seq")

if __name__ == "__main__":
    generate_nist_sequence()
