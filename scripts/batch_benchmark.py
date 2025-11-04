# scripts/batch_benchmark.py
# Читає рядки з data/messages.txt -> багаторазово (--repeat N) шифрує/розшифровує
# кожен рядок з ОДНИМ K0/Γ на всю сесію -> пише 2 CSV + будує графік.
# Варіанти A,C:
#   A) фіксована сіль на повідомлення (прибирає шум os.urandom з таймінгу);
#   C) робастні агрегати: median + trimmed mean; графік малюємо по медіані.

from __future__ import annotations
from typing import List, Tuple, Dict, Optional
from pathlib import Path
import argparse
import csv
import time
import statistics as stats
from statistics import median
import gc

from crypto.matrix_stream_cipher import (
    generate_random_1024, compress_1024_to_64,
    normalize_quaternion_from_k0, gamma_from_quaternion,
    pack_M0_from_text, unpack_M0_to_bytes,
    pack_u64_stream_no_pad, unpack_u64_stream_to_bytes,
    matmul3, transpose3, g_next, MASK64,
    gamma_chain_no_pad,
)
from helpers.salt import generate_salt


# -------------------- paths & utils --------------------

def project_paths() -> Tuple[Path, Path, Path, Path, Path, Path]:
    """
    Повертає кортеж шляхів:
      root, messages.txt, cipher_results.csv, cipher_speed_by_length.csv, cipher_len_time.png, cipher_len_time.svg
    """
    here = Path(__file__).resolve()
    root = here.parents[1]
    msg = root / "data" / "messages.txt"
    out_results = root / "data" / "cipher_results.csv"
    out_speed = root / "data" / "cipher_speed_by_length.csv"
    out_png = root / "data" / "cipher_len_time.png"
    out_svg = root / "data" / "cipher_len_time.svg"
    return root, msg, out_results, out_speed, out_png, out_svg


def mb_per_s(len_bytes: int, ms: float) -> float:
    """Обчислити MB/s за довжиною повідомлення (байти) та часом (мс)."""
    if ms <= 0:
        return float("inf")
    return (len_bytes / 1_048_576.0) * (1000.0 / ms)


def trimmed_mean(values: List[float], p: float = 0.1) -> float:
    """Обрізане середнє: відкидаємо p частку знизу і згори (за замовчуванням 10%)."""
    if not values:
        return float("nan")
    n = len(values)
    if n == 1:
        return values[0]
    k = int(n * p)
    vals = sorted(values)
    if 2 * k >= n:
        return stats.fmean(vals)  # замало значень для обрізання
    core = vals[k : n - k]
    return stats.fmean(core)


# -------------------- crypto one-shots --------------------

def encrypt_one(
    msg_bytes: bytes,
    K0: int,
    Gamma: List[List[int]],
    mac_salt_b64: Optional[str] = None,  # A) фіксована сіль: якщо задана — не генеруємо
):
    """
    Узгоджено з реалізацією без падингу гами:
      • Формуємо M0 та 'rest' (байти), збираємо M0_bytes18.
      • C0 = Γ · M0.
      • gamma_chain_no_pad(K0, M0_bytes18, rest, salt) -> g_trace і фінальний g.
      • Потоковий XOR лише для 'rest' (64-бітні слова).
      • MAC = фінальний g (обрізаний до 64 біт).
    """
    # 1) Пакування M0 і решти
    M0, rest, M0_bytes18 = pack_M0_from_text(msg_bytes)

    # 2) Перший блок
    C0 = matmul3(Gamma, M0)

    # 3) Ланцюг гами (A)
    if mac_salt_b64 is None:
        mac_salt_b64 = generate_salt(8)
    g_final, g_trace = gamma_chain_no_pad(K0, M0_bytes18, rest, mac_salt_b64)

    # 4) Потокове шифрування лише для 'rest'
    g_prev = g_trace[3] if len(g_trace) >= 4 else g_trace[-1]
    X = pack_u64_stream_no_pad(rest)

    C_stream: List[int] = []
    for xi in X:
        ci = (xi ^ g_prev) & MASK64
        C_stream.append(ci)
        g_prev = g_next(xi, g_prev)

    mac = int(g_final & MASK64)
    return C0, C_stream, mac, mac_salt_b64


def decrypt_one(C0, C_stream, K0, Gamma, mac_expected, mac_salt_b64, orig_len: int):
    """
    Зворотні кроки:
      • M0_dec = Γ^T · C0.
      • Відтворити g після M0, потім розкодовувати 'rest'.
      • Підтвердити MAC через повний gamma_chain_no_pad.
      • Повернути відновлені байти (обрізати до orig_len) і прапорець mac_ok.
    """
    # 1) Відновлення M0
    M0_dec = matmul3(transpose3(Gamma), C0)
    first18 = unpack_M0_to_bytes(M0_dec)

    # 2) g після M0
    g_after_m0 = gamma_chain_no_pad(K0, first18, b"", mac_salt_b64)[1][-1]

    # 3) Дешифр решти
    X_dec: List[int] = []
    g_prev = g_after_m0
    for ci in C_stream:
        xi = (int(ci) ^ g_prev) & MASK64
        X_dec.append(xi)
        g_prev = g_next(xi, g_prev)
    rest_bytes = unpack_u64_stream_to_bytes(X_dec)

    # 4) MAC перевірка
    mac_check, _ = gamma_chain_no_pad(K0, first18, rest_bytes, mac_salt_b64)
    mac_ok = (int(mac_check & MASK64) == int(mac_expected & MASK64))

    recovered = (first18 + rest_bytes)[:orig_len]
    return recovered, mac_ok


# -------------------- plotting --------------------

def make_plot(per_len: Dict[int, Dict[str, List[float]]], png_path: Path, svg_path: Path) -> None:
    """Побудова графіка МЕДІАННОГО часу (мс) залежно від довжини (байти)."""
    try:
        import matplotlib.pyplot as plt  # noqa: WPS433
    except Exception:
        print("[WARN] matplotlib не встановлено – пропускаю побудову графіка.")
        return

    lengths = sorted(per_len.keys())
    if not lengths:
        print("[WARN] Немає даних для графіка.")
        return

    # C) будуємо по медіані
    enc_med = [median(per_len[L]["enc_ms"]) for L in lengths]
    dec_med = [median(per_len[L]["dec_ms"]) for L in lengths]

    plt.figure(figsize=(8, 5))
    plt.plot(lengths, enc_med, marker="o", linewidth=1.5, label="Зашифрування (медіана, мс)")
    plt.plot(lengths, dec_med, marker="s", linewidth=1.5, label="Розшифрування (медіана, мс)")
    plt.xlabel("Довжина повідомлення, байт")
    plt.ylabel("Час, мс (медіана)")
    plt.title("Залежність часу від довжини повідомлення")
    plt.grid(True, alpha=0.3)
    plt.legend()
    png_path.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(png_path, dpi=150)
    plt.savefig(svg_path)
    plt.close()
    print(f"[OK] Графік збережено: {png_path} (та {svg_path})")


# -------------------- main --------------------

def main():
    # CLI тільки для керування кількістю повторів і warmup
    ap = argparse.ArgumentParser(description="Бенчмарк messages.txt з одним K0/Γ і повтореннями вимірювань.")
    ap.add_argument("--repeat", type=int, default=10,
                    help="Скільки разів повторювати encrypt→decrypt для КОЖНОГО рядка (за замовчуванням 10).")
    ap.add_argument("--warmup", type=int, default=3,
                    help="Скільки холостих прогонів зробити перед вимірюваннями (за замовчуванням 3).")
    args = ap.parse_args()
    repeats = max(1, args.repeat)
    warmup = max(0, args.warmup)

    # 1) Шляхи і наявність вхідного файлу
    root, msgs_path, csv_results_path, csv_speed_path, png_path, svg_path = project_paths()
    if not msgs_path.exists():
        raise FileNotFoundError(f"Не знайдено файл з повідомленнями: {msgs_path}")

    # 2) ЄДИНИЙ ключ на сесію: генеруємо 1024-бітний, стискаємо до K0, будуємо Γ(q̂)
    K = generate_random_1024()
    K0 = compress_1024_to_64(K)
    w, x, y, z, *_ = normalize_quaternion_from_k0(K0)
    Gamma = gamma_from_quaternion(w, x, y, z)
    print(f"[INFO] Використовую єдиний K0 (hex) = 0x{K0:016x}")
    print(f"[INFO] Повтори: {repeats}, warmup: {warmup}")

    # 3) Зчитати повідомлення (тільки з data/messages.txt)
    lines = [ln.rstrip("\n") for ln in msgs_path.read_text(encoding="utf-8").splitlines()]
    messages = [s for s in lines if s.strip() != ""]
    if not messages:
        print("[ERR] Файл повідомлень порожній.")
        return

    # 4) Накопичення метрик по довжинах
    per_len: Dict[int, Dict[str, List[float]]] = {}  # len_bytes -> {"enc_ms": [...], "dec_ms": [...]}
    ok_count = 0

    # 5) Основний цикл: шифрування + розшифрування з повтореннями
    for msg in messages:
        msg_bytes = msg.encode("utf-8")
        L = len(msg_bytes)

        # A) фіксована сіль на повідомлення: прибирає шум os.urandom із таймінгу
        salt_fixed = generate_salt(8)

        # короткий warmup (без обліку часу) на перший крок цього рядка
        for _ in range(warmup):
            C0_w, Cstream_w, mac_w, salt_w = encrypt_one(msg_bytes, K0, Gamma, salt_fixed)
            _rec, _ok = decrypt_one(C0_w, Cstream_w, K0, Gamma, mac_w, salt_w, L)

        # вимірювання
        for _ in range(repeats):
            gc.disable()
            t0 = time.perf_counter_ns()
            C0, C_stream, mac, mac_salt_b64 = encrypt_one(msg_bytes, K0, Gamma, salt_fixed)
            t1 = time.perf_counter_ns()
            recovered, mac_ok = decrypt_one(C0, C_stream, K0, Gamma, mac, mac_salt_b64, L)
            t2 = time.perf_counter_ns()
            gc.enable()

            enc_ms = (t1 - t0) / 1e6
            dec_ms = (t2 - t1) / 1e6

            if mac_ok and recovered == msg_bytes:
                ok_count += 1

            bucket = per_len.setdefault(L, {"enc_ms": [], "dec_ms": []})
            bucket["enc_ms"].append(enc_ms)
            bucket["dec_ms"].append(dec_ms)

        # збірка сміття між різними довжинами (не між повторами)
        gc.collect()

    # 6) CSV #1: один рядок на довжину з робастними агрегатами (C)
    csv_results_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_results_path.open("w", newline="", encoding="utf-8") as f:
        wcsv = csv.writer(f)
        wcsv.writerow([
            "len_bytes",
            "count",
            "enc_ms(min/median/mean/max)",
            "dec_ms(min/median/mean/max)",
            "enc_MBps_mean",
            "enc_ms_trimmed_mean",
            "dec_ms_trimmed_mean",
        ])
        for L in sorted(per_len.keys()):
            enc_list = per_len[L]["enc_ms"]
            dec_list = per_len[L]["dec_ms"]
            count = len(enc_list)

            enc_min, enc_med, enc_mean, enc_max = min(enc_list), median(enc_list), stats.fmean(enc_list), max(enc_list)
            dec_min, dec_med, dec_mean, dec_max = min(dec_list), median(dec_list), stats.fmean(dec_list), max(dec_list)
            enc_MBps_mean = stats.fmean([mb_per_s(L, v) for v in enc_list])
            enc_tmean = trimmed_mean(enc_list, 0.1)
            dec_tmean = trimmed_mean(dec_list, 0.1)

            enc_stats = f"{enc_min:.3f}/{enc_med:.3f}/{enc_mean:.3f}/{enc_max:.3f}"
            dec_stats = f"{dec_min:.3f}/{dec_med:.3f}/{dec_mean:.3f}/{dec_max:.3f}"
            wcsv.writerow([
                L, count, enc_stats, dec_stats,
                f"{enc_MBps_mean:.6f}",
                f"{enc_tmean:.6f}",
                f"{dec_tmean:.6f}",
            ])

    # 7) CSV #2: компакт-зведена (залишаємо середні для сумісності)
    with csv_speed_path.open("w", newline="", encoding="utf-8") as f2:
        wagg = csv.writer(f2)
        wagg.writerow(["len_bytes", "count", "enc_ms_mean", "enc_ms_median", "dec_ms_mean", "dec_ms_median", "enc_MBps_mean"])
        for L in sorted(per_len.keys()):
            enc_list = per_len[L]["enc_ms"]
            dec_list = per_len[L]["dec_ms"]
            count = len(enc_list)
            enc_mean = stats.fmean(enc_list)
            dec_mean = stats.fmean(dec_list)
            enc_med = median(enc_list)
            dec_med = median(dec_list)
            enc_MBps_mean = stats.fmean([mb_per_s(L, v) for v in enc_list])
            wagg.writerow([
                L, count,
                f"{enc_mean:.6f}", f"{enc_med:.6f}",
                f"{dec_mean:.6f}", f"{dec_med:.6f}",
                f"{enc_MBps_mean:.6f}",
            ])

    # 8) Побудова графіка (по медіані)
    make_plot(per_len, png_path, svg_path)

    # 9) Статус
    total_msgs = sum(len(v["enc_ms"]) for v in per_len.values())
    print(f"[OK] Опрацьовано {total_msgs} вимірювань (усі рядки × repeat), успішно відновлено: {ok_count}.")
    print(f"[OK] Зведені результати (робастні агрегати): {csv_results_path}")
    print(f"[OK] Додаткова зведена таблиця: {csv_speed_path}")
    print(f"[OK] Графіки (медіана): {png_path}, {svg_path}")


if __name__ == "__main__":
    main()
