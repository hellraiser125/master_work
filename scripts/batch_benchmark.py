# scripts/benchmark_speed.py
"""
Бенчмарк швидкості шифрування/розшифрування:

1) Вимірювання швидкості власного шифру (matrix_stream_cipher no-pad).
2) Порівняння з AES-GCM та ChaCha20-Poly1305 (якщо доступні).

Результат:
 - таблиці в консолі:
      • детальна для мого шифру;
      • зведена порівняльна для всіх алгоритмів.
 - CSV-файли в ../data/ :
      results_my_cipher.csv
      results_aes_gcm.csv
      results_chacha20_poly1305.csv
      results_compare.csv
 - графіки в ../data/ :
      my_cipher_time_us.png
      compare_encrypt_time_us.png
      compare_decrypt_time_us.png
"""

from __future__ import annotations

import time
import statistics
import csv
import math
import secrets
import argparse
from dataclasses import dataclass
from typing import Callable, Dict, List, Tuple, Any
from pathlib import Path

# --- Твій шифр (базуємося на main_demo.py) ---
from crypto.matrix_stream_cipher import (
    generate_random_1024,
    compress_1024_to_64,
    normalize_quaternion_from_k0,
    gamma_from_quaternion,
    pack_M0_from_text,
    unpack_M0_to_bytes,
    pack_u64_stream_no_pad,
    unpack_u64_stream_to_bytes,
    matmul3,
    transpose3,
    g_next,
    MASK64,
    gamma_chain_no_pad,
)

from helpers.salt import generate_salt

# --- опційні залежності ---

# гарні таблиці
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.box import ROUNDED

    console = Console()
    USE_RICH = True
except Exception:
    console = None
    USE_RICH = False

# графіки
try:
    import matplotlib.pyplot as plt

    USE_MPL = True
except Exception:
    USE_MPL = False

# популярні шифри
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False


# ===================== Шлях до data/ =====================

# scripts/benchmark_speed.py -> корінь проєкту -> data/
BASE_DIR = Path(__file__).resolve().parent          # .../scripts
DATA_DIR = BASE_DIR.parent / "data"                 # .../data
DATA_DIR.mkdir(parents=True, exist_ok=True)


# ===================== Реалізація твого шифру у вигляді API =====================

@dataclass
class MyCipherPacket:
    """Упаковка результату шифрування для твого шифру."""
    C0: List[List[int]]          # матричний блок 3x3
    C_stream: List[int]          # потокові 64-бітні блоки
    mac: int                     # MAC = final g (64 біти)
    mac_salt_b64: str            # сіль для MAC/гами
    orig_len: int                # вихідна довжина повідомлення в байтах


@dataclass
class MyCipherContext:
    """Контекст: ключ і матриця Γ(q̂), щоб не рахувати її кожного разу."""
    K0: int
    Gamma: List[List[int]]


def create_my_cipher_context() -> MyCipherContext:
    """Генерує один K (1024 біт) → K0 (64 біти) → Γ(q̂)."""
    K = generate_random_1024()
    K0 = compress_1024_to_64(K)
    w, x, y, z, t, d, N, dbg = normalize_quaternion_from_k0(K0)
    Gamma = gamma_from_quaternion(w, x, y, z)
    return MyCipherContext(K0=K0, Gamma=Gamma)


def my_cipher_encrypt(ctx: MyCipherContext, msg: bytes) -> MyCipherPacket:
    """Шифрування повідомлення за твоїм алгоритмом (no-pad, MAC = final g)."""
    K0 = ctx.K0
    Gamma = ctx.Gamma

    # M0 (перші 18 байт) + решта
    M0, rest, M0_bytes18 = pack_M0_from_text(msg)
    C0 = matmul3(Gamma, M0)

    # одна сіль на весь ланцюг
    mac_salt_b64 = generate_salt(8)

    # гама-ланцюг без падингу
    g_final, g_trace = gamma_chain_no_pad(K0, M0_bytes18, rest, mac_salt_b64)

    # потокова частина (якщо решта не порожня)
    g_prev = g_trace[3] if len(g_trace) >= 4 else g_trace[-1]
    X = pack_u64_stream_no_pad(rest)
    C_stream: List[int] = []
    g_vals: List[int] = [g_prev]
    for xi in X:
        gi_1 = g_vals[-1]
        ci = (xi ^ gi_1) & MASK64
        C_stream.append(ci)
        gi = g_next(xi, gi_1)
        g_vals.append(gi)

    mac = int(g_final & MASK64)
    return MyCipherPacket(
        C0=C0,
        C_stream=C_stream,
        mac=mac,
        mac_salt_b64=mac_salt_b64,
        orig_len=len(msg),
    )


def my_cipher_decrypt(ctx: MyCipherContext, packet: MyCipherPacket) -> bytes:
    """Розшифрування + перевірка MAC (кине ValueError, якщо MAC не збігся)."""
    K0 = ctx.K0
    Gamma = ctx.Gamma

    # відновити M0
    M0_dec = matmul3(transpose3(Gamma), packet.C0)
    first18 = unpack_M0_to_bytes(M0_dec)

    # гама після M0
    g_after_m0 = gamma_chain_no_pad(K0, first18, b"", packet.mac_salt_b64)[1][-1]

    # розшифрувати потік
    X_dec: List[int] = []
    g_prev = g_after_m0
    for ci in packet.C_stream:
        xi = (int(ci) ^ g_prev) & MASK64
        X_dec.append(xi)
        g_prev = g_next(xi, g_prev)

    rest_bytes = unpack_u64_stream_to_bytes(X_dec)

    # повне повідомлення (усічене до orig_len)
    full_plain = (first18 + rest_bytes)[: packet.orig_len]

    # перевірка MAC
    mac_check, _ = gamma_chain_no_pad(K0, first18, rest_bytes, packet.mac_salt_b64)
    if (mac_check & MASK64) != (packet.mac & MASK64):
        raise ValueError("MAC mismatch in my cipher")

    return full_plain


# ============================ Бенчмарк-утиліти ============================

@dataclass
class BenchResult:
    size: int
    enc_mean_us: float
    dec_mean_us: float
    enc_std_us: float
    dec_std_us: float
    enc_mb_per_s: float
    dec_mb_per_s: float


def prepare_plaintexts(sizes: List[int], total_samples: int) -> Dict[int, List[bytes]]:
    """Готуємо набір випадкових повідомлень для кожної довжини."""
    data: Dict[int, List[bytes]] = {}
    for sz in sizes:
        data[sz] = [secrets.token_bytes(sz) for _ in range(total_samples)]
    return data


def benchmark_algorithm(
    name: str,
    sizes: List[int],
    plaintexts: Dict[int, List[bytes]],
    encrypt: Callable[[bytes], Any],
    decrypt: Callable[[Any], bytes],
    warmup: int = 10,
    reps: int = 50,
) -> List[BenchResult]:
    """
    Вимірює час шифрування/розшифрування.

    warmup — скільки перших ітерацій ми проганяємо "вхолосту" (результат не міряємо),
    reps   — скільки ітерацій записуємо в статистику.
    """
    if USE_RICH:
        console.rule(f"[bold green]Бенчмарк: {name}")

    total_samples = warmup + reps
    results: List[BenchResult] = []

    for sz in sizes:
        pts = plaintexts[sz]
        if len(pts) < total_samples:
            raise ValueError("Недостатньо plaintext'ів для розміру", sz)

        # warmup: проганяємо, але не міряємо, тільки перевіряємо коректність
        for i in range(warmup):
            pt = pts[i]
            obj = encrypt(pt)
            dec = decrypt(obj)
            if dec != pt:
                raise ValueError(f"{name}: помилка розшифрування на warmup (size={sz})")

        # measured
        enc_times: List[float] = []
        dec_times: List[float] = []

        for i in range(warmup, warmup + reps):
            pt = pts[i]

            t0 = time.perf_counter()
            obj = encrypt(pt)
            t1 = time.perf_counter()
            _ = decrypt(obj)
            t2 = time.perf_counter()

            enc_times.append(t1 - t0)
            dec_times.append(t2 - t1)

        # статистика
        enc_mean = statistics.mean(enc_times)
        dec_mean = statistics.mean(dec_times)
        enc_std = statistics.pstdev(enc_times) if len(enc_times) > 1 else 0.0
        dec_std = statistics.pstdev(dec_times) if len(dec_times) > 1 else 0.0

        # перетворюємо в мікросекунди та MB/s
        enc_mean_us = enc_mean * 1e6
        dec_mean_us = dec_mean * 1e6
        enc_std_us = enc_std * 1e6
        dec_std_us = dec_std * 1e6

        mb = sz / 1e6
        enc_mbps = mb / enc_mean if enc_mean > 0 else math.inf
        dec_mbps = mb / dec_mean if dec_mean > 0 else math.inf

        res = BenchResult(
            size=sz,
            enc_mean_us=enc_mean_us,
            dec_mean_us=dec_mean_us,
            enc_std_us=enc_std_us,
            dec_std_us=dec_std_us,
            enc_mb_per_s=enc_mbps,
            dec_mb_per_s=dec_mbps,
        )
        results.append(res)

    return results


def save_results_csv(path: Path, algo_name: str, results: List[BenchResult]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "algo",
                "size_bytes",
                "enc_mean_us",
                "enc_std_us",
                "dec_mean_us",
                "dec_std_us",
                "enc_MBps",
                "dec_MBps",
            ]
        )
        for r in results:
            w.writerow(
                [
                    algo_name,
                    r.size,
                    f"{r.enc_mean_us:.2f}",
                    f"{r.enc_std_us:.2f}",
                    f"{r.dec_mean_us:.2f}",
                    f"{r.dec_std_us:.2f}",
                    f"{r.enc_mb_per_s:.2f}",
                    f"{r.dec_mb_per_s:.2f}",
                ]
            )


def print_results_table(algo_name: str, results: List[BenchResult]) -> None:
    """Детальна таблиця тільки для мого шифру."""
    if not USE_RICH:
        print(f"\n=== {algo_name} ===")
        print("size | enc_mean_us | dec_mean_us | enc_MB/s | dec_MB/s")
        for r in results:
            print(
                f"{r.size:5d} | {r.enc_mean_us:11.1f} | {r.dec_mean_us:11.1f} | "
                f"{r.enc_mb_per_s:8.1f} | {r.dec_mb_per_s:8.1f}"
            )
        return

    t = Table(
        title=f"Результати бенчмарку: {algo_name}",
        box=ROUNDED,
        show_footer=False,
    )
    t.add_column("size, байт", justify="right", style="cyan")
    t.add_column("enc, мкс", justify="right", style="magenta")
    t.add_column("dec, мкс", justify="right", style="magenta")
    t.add_column("enc, MB/s", justify="right", style="green")
    t.add_column("dec, MB/s", justify="right", style="green")

    for r in results:
        t.add_row(
            str(r.size),
            f"{r.enc_mean_us:.1f}",
            f"{r.dec_mean_us:.1f}",
            f"{r.enc_mb_per_s:.1f}",
            f"{r.dec_mb_per_s:.1f}",
        )
    console.print(t)


def print_compare_table(all_results: Dict[str, List[BenchResult]]) -> None:
    """Одна зведена таблиця для всіх алгоритмів."""
    # будуємо map: algo -> {size: BenchResult}
    size_set = set()
    per_algo: Dict[str, Dict[int, BenchResult]] = {}
    for algo, res_list in all_results.items():
        d: Dict[int, BenchResult] = {}
        for r in res_list:
            d[r.size] = r
            size_set.add(r.size)
        per_algo[algo] = d

    sizes_sorted = sorted(size_set)

    if not USE_RICH:
        # простий текстовий формат
        header = ["size"]
        for algo in all_results.keys():
            header.append(f"{algo}_enc_us")
            header.append(f"{algo}_dec_us")
        print("\n=== Порівняльна таблиця ===")
        print(" | ".join(header))
        for sz in sizes_sorted:
            row = [str(sz)]
            for algo in all_results.keys():
                r = per_algo[algo].get(sz)
                if r is None:
                    row.extend(["-", "-"])
                else:
                    row.append(f"{r.enc_mean_us:.1f}")
                    row.append(f"{r.dec_mean_us:.1f}")
            print(" | ".join(row))
        return

    # rich-таблиця
    t = Table(
        title="Порівняння алгоритмів (encrypt/decrypt, мкс)",
        box=ROUNDED,
        show_footer=False,
    )
    t.add_column("size, байт", justify="right", style="cyan")
    for algo in all_results.keys():
        t.add_column(f"{algo} enc, мкс", justify="right", style="magenta")
        t.add_column(f"{algo} dec, мкс", justify="right", style="green")

    for sz in sizes_sorted:
        row = [str(sz)]
        for algo in all_results.keys():
            r = per_algo[algo].get(sz)
            if r is None:
                row.append("-")
                row.append("-")
            else:
                row.append(f"{r.enc_mean_us:.1f}")
                row.append(f"{r.dec_mean_us:.1f}")
        t.add_row(*row)

    console.print(t)


def plot_single_algo(results: List[BenchResult], path: Path, title: str) -> None:
    if not USE_MPL:
        return
    sizes = [r.size for r in results]
    enc = [r.enc_mean_us for r in results]
    dec = [r.dec_mean_us for r in results]

    plt.figure(figsize=(8, 5))
    plt.plot(sizes, enc, marker="o", label="Encrypt")
    plt.plot(sizes, dec, marker="s", label="Decrypt")
    plt.xlabel("Розмір повідомлення, байт")
    plt.ylabel("Час, мкс")
    plt.title(title)
    plt.grid(True, linestyle="--", alpha=0.4)
    plt.legend()
    plt.tight_layout()
    plt.savefig(str(path), dpi=150)
    plt.close()


def plot_compare(
    all_results: Dict[str, List[BenchResult]],
    path: Path,
    title: str,
    which: str = "enc",
) -> None:
    """
    all_results: {algo_name: [BenchResult, ...]}
    which: 'enc' або 'dec'
    """
    if not USE_MPL:
        return

    plt.figure(figsize=(8, 5))
    for algo, results in all_results.items():
        sizes = [r.size for r in results]
        if which == "enc":
            vals = [r.enc_mean_us for r in results]
            label = f"{algo} enc"
        else:
            vals = [r.dec_mean_us for r in results]
            label = f"{algo} dec"

        plt.plot(sizes, vals, marker="o", label=label)

    plt.xlabel("Розмір повідомлення, байт")
    plt.ylabel("Час, мкс")
    plt.title(title)
    plt.grid(True, linestyle="--", alpha=0.4)
    plt.legend()
    plt.tight_layout()
    plt.savefig(str(path), dpi=150)
    plt.close()


# =============================== CLI ===============================

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Бенчмарк швидкості шифрування/розшифрування."
    )
    p.add_argument(
        "--warmup",
        type=int,
        default=10,
        help="кількість розігрівочних ітерацій без вимірювання (default: 10)",
    )
    p.add_argument(
        "--reps",
        type=int,
        default=50,
        help="кількість вимірюваних ітерацій (default: 50)",
    )
    p.add_argument(
        "--sizes",
        type=int,
        nargs="+",
        default=[16, 32, 64, 128, 256, 512, 1024, 2048, 4096],
        help="список розмірів повідомлень у байтах",
    )
    return p.parse_args()


# =============================== main() ===============================

def main():
    args = parse_args()
    sizes = args.sizes
    warmup = args.warmup
    reps = args.reps
    total_samples = warmup + reps

    if USE_RICH:
        console.rule("[bold yellow]Підготовка даних для бенчмарку")
        console.print(
            Panel(
                f"Розміри повідомлень: {sizes}\n"
                f"warmup = {warmup} (ітерацій без вимірювання)\n"
                f"reps   = {reps} (ітерацій з вимірюванням)\n"
                f"Разом зразків на розмір: {total_samples}\n"
                f"Файли результатів будуть збережені в: {DATA_DIR}",
                title="Параметри тестування",
                border_style="yellow",
            )
        )
    else:
        print("Готуємо plaintext-и для розмірів:", sizes)
        print("warmup =", warmup, "reps =", reps)
        print("Результати будуть у папці:", DATA_DIR)

    plaintexts = prepare_plaintexts(sizes, total_samples)

    # ---------- 1. Тест тільки твого шифру ----------
    ctx_my = create_my_cipher_context()

    def my_enc(pt: bytes) -> MyCipherPacket:
        return my_cipher_encrypt(ctx_my, pt)

    def my_dec(pkt: MyCipherPacket) -> bytes:
        return my_cipher_decrypt(ctx_my, pkt)

    results_my = benchmark_algorithm(
        "Мій шифр (matrix_stream_cipher no-pad)",
        sizes,
        plaintexts,
        encrypt=my_enc,
        decrypt=my_dec,
        warmup=warmup,
        reps=reps,
    )

    print_results_table("Мій шифр", results_my)
    save_results_csv(DATA_DIR / "results_my_cipher.csv", "my_cipher", results_my)
    plot_single_algo(
        results_my,
        DATA_DIR / "my_cipher_time_us.png",
        "Швидкість мого шифру (encrypt/decrypt)",
    )

    # ---------- 2. Порівняння з AES-GCM та ChaCha20-Poly1305 ----------
    all_results: Dict[str, List[BenchResult]] = {"MyCipher": results_my}

    if not HAVE_CRYPTO:
        if USE_RICH:
            console.print(
                Panel(
                    "Модуль 'cryptography' не знайдено. "
                    "Порівняльний тест з AES-GCM та ChaCha20-Poly1305 пропущено.\n"
                    "Встанови: pip install cryptography",
                    title="Попередження",
                    border_style="red",
                )
            )
        else:
            print(
                "WARNING: 'cryptography' не встановлено, "
                "пропускаю порівняння з AES-GCM/ChaCha20-Poly1305."
            )
    else:
        # AES-GCM (256-bit key)
        key_aes = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(key_aes)

        def aes_enc(pt: bytes) -> Tuple[bytes, bytes]:
            nonce = secrets.token_bytes(12)  # 96-бітний nonce
            ct = aesgcm.encrypt(nonce, pt, associated_data=None)
            return nonce, ct

        def aes_dec(obj: Tuple[bytes, bytes]) -> bytes:
            nonce, ct = obj
            return aesgcm.decrypt(nonce, ct, associated_data=None)

        results_aes = benchmark_algorithm(
            "AES-GCM (256-bit)",
            sizes,
            plaintexts,
            encrypt=aes_enc,
            decrypt=aes_dec,
            warmup=warmup,
            reps=reps,
        )
        save_results_csv(DATA_DIR / "results_aes_gcm.csv", "aes_gcm", results_aes)
        all_results["AES-GCM"] = results_aes

        # ChaCha20-Poly1305 (256-bit key)
        key_chacha = ChaCha20Poly1305.generate_key()
        chacha = ChaCha20Poly1305(key_chacha)

        def chacha_enc(pt: bytes) -> Tuple[bytes, bytes]:
            nonce = secrets.token_bytes(12)
            ct = chacha.encrypt(nonce, pt, associated_data=None)
            return nonce, ct

        def chacha_dec(obj: Tuple[bytes, bytes]) -> bytes:
            nonce, ct = obj
            return chacha.decrypt(nonce, ct, associated_data=None)

        results_chacha = benchmark_algorithm(
            "ChaCha20-Poly1305",
            sizes,
            plaintexts,
            encrypt=chacha_enc,
            decrypt=chacha_dec,
            warmup=warmup,
            reps=reps,
        )
        save_results_csv(
            DATA_DIR / "results_chacha20_poly1305.csv",
            "chacha20_poly1305",
            results_chacha,
        )
        all_results["ChaCha20-Poly1305"] = results_chacha

        # зведена таблиця в один CSV
        with (DATA_DIR / "results_compare.csv").open(
            "w", newline="", encoding="utf-8"
        ) as f:
            w = csv.writer(f)
            w.writerow(
                [
                    "algo",
                    "size_bytes",
                    "enc_mean_us",
                    "enc_std_us",
                    "dec_mean_us",
                    "dec_std_us",
                    "enc_MBps",
                    "dec_MBps",
                ]
            )
            for algo_name, res_list in all_results.items():
                for r in res_list:
                    w.writerow(
                        [
                            algo_name,
                            r.size,
                            f"{r.enc_mean_us:.2f}",
                            f"{r.enc_std_us:.2f}",
                            f"{r.dec_mean_us:.2f}",
                            f"{r.dec_std_us:.2f}",
                            f"{r.enc_mb_per_s:.2f}",
                            f"{r.dec_mb_per_s:.2f}",
                        ]
                    )

        # графіки: порівняння
        plot_compare(
            all_results,
            DATA_DIR / "compare_encrypt_time_us.png",
            "Порівняння часу шифрування (encrypt)",
            which="enc",
        )
        plot_compare(
            all_results,
            DATA_DIR / "compare_decrypt_time_us.png",
            "Порівняння часу розшифрування (decrypt)",
            which="dec",
        )

        # одна спільна таблиця з усіма алгоритмами
        print_compare_table(all_results)

    if USE_RICH:
        console.rule("[bold magenta]Бенчмарк завершено")
    else:
        print("Готово. Перевір результати в папці:", DATA_DIR)


if __name__ == "__main__":
    main()
