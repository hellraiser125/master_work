# main.py — симуляція: обмін K0 -> локальне нормування -> шифрування/дешифрування
# ПІД НОВИЙ ШИФР (NO-PAD): гама: M0 ➜ rest, без ISO-падингу; MAC = фінальний g.
# Додано: коли rest порожній, показуємо кроки формування гами саме для M0.

from typing import List, Tuple

from crypto.matrix_stream_cipher import (
    # крок обміну:
    generate_random_1024, compress_1024_to_64,
    # локальне нормування:
    normalize_quaternion_from_k0, gamma_from_quaternion,
    # будівельні блоки нового шифру:
    pack_M0_from_text, unpack_M0_to_bytes,
    pack_u64_stream_no_pad, unpack_u64_stream_to_bytes,
    matmul3, transpose3, g_next, P, MASK64,
    gamma_chain_no_pad, m0_words_no_pad,           # ← важливо: імпортуємо m0_words_no_pad
)

# сіль використовуємо одну й ту ж у Alice/Bob
from helpers.salt import generate_salt

# ---- optional fallback if rich not installed ----
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.text import Text
    from rich.box import SIMPLE_HEAVY, ROUNDED
    from rich.prompt import Prompt
except Exception:
    Console = None

def fmt_hex(n: int, width: int | None = None) -> str:
    if width is None:
        return f"0x{n:x}"
    return f"0x{n:0{width}x}"

def make_matrix_table(name: str, M: List[List[int]]) -> Table:
    t = Table(title=name + f"  (mod {P})", box=ROUNDED, show_header=False, pad_edge=False)
    t.add_column(justify="right", style="cyan")
    t.add_column(justify="right", style="cyan")
    t.add_column(justify="right", style="cyan")
    for row in M:
        t.add_row(*[str(v % P).rjust(6) for v in row])
    return t

def make_words64_table(title: str, arr: List[int]) -> Table:
    t = Table(title=title, box=SIMPLE_HEAVY)
    t.add_column("#", justify="right", style="bold cyan")
    t.add_column("Hex", style="magenta")
    t.add_column("Dec", style="white")
    if not arr:
        t.add_row("-", "<порожньо>", "")
        return t
    for i, v in enumerate(arr, 1):
        t.add_row(f"{i:02d}", fmt_hex(v, 16), str(v))
    return t

def identity3() -> List[List[int]]: return [[1,0,0],[0,1,0],[0,0,1]]

def is_identity_mod_p(M) -> bool:
    I = identity3()
    for i in range(3):
        for j in range(3):
            if M[i][j] % P != I[i][j]:
                return False
    return True

def make_norm_panel(side: str, K0: int, w: int, x: int, y: int, z: int, t: int, delta_z: int, N_before: int, norm_dbg: dict):
    t_alt = (P - t) % P
    passport = Table(box=ROUNDED, show_header=False, pad_edge=False)
    passport.add_column("k", style="bold"); passport.add_column("v")
    passport.add_row("K0 (64-bit)",  f"{fmt_hex(K0,16)}  ({K0})")
    passport.add_row("q_raw (from K0)", str(norm_dbg["wxyz_raw"]))
    passport.add_row("Δz (chosen)", str(delta_z))
    passport.add_row("N (at chosen Δz)", str(N_before))
    passport.add_row("invN", str(norm_dbg["chosen"]["invN"]))
    passport.add_row("sqrt(invN) candidates", f"{t}, {t_alt}")
    passport.add_row("t (chosen)", str(t))
    passport.add_row("q̂ = (w,x,y,z)", f"({w}, {x}, {y}, {z})")
    passport.add_row("‖q̂‖² mod 65537", str(norm_dbg["chosen"]["norm_after"]))
    return Panel(passport, title=f"[{side}] Локальне нормування q̂", border_style="green")

def print_stream_steps(console: Console, X: List[int], C_stream: List[int], g_vals: List[int]):
    t = Table(title="Кроки потокового шифрування", box=SIMPLE_HEAVY)
    t.add_column("i", justify="right", style="bold cyan")
    t.add_column("X_i (hex)", style="magenta")
    t.add_column("g_(i-1) (hex)", style="yellow")
    t.add_column("C_i = X_i XOR g_(i-1)", style="bold white")
    t.add_column("g_i = f64(X_i, g_(i-1))", style="green")
    for i, xi in enumerate(X, 1):
        t.add_row(
            f"{i:02d}",
            fmt_hex(xi, 16),
            fmt_hex(g_vals[i-1], 16),
            fmt_hex(C_stream[i-1], 16),
            fmt_hex(g_vals[i], 16),
        )
    console.print(t)

# --- НОВЕ: показати кроки формування гами саме для M0 (коли rest порожній)
def print_gamma_steps_for_m0(console: Console, m0_words: List[int], g_trace: List[int]):
    """
    Показує три кроки гами для M0.
    g_trace: [g0, g1, g2, g3, ...]; для M0 беремо пари (g_(i-1), g_i) на i=1..3.
    """
    t = Table(title="Кроки формування гами для M₀", box=SIMPLE_HEAVY)
    t.add_column("i", justify="right", style="bold cyan")
    t.add_column("X_i (hex)", style="magenta")
    t.add_column("g_(i-1) (hex)", style="yellow")
    t.add_column("g_i = f64(X_i, g_(i-1))", style="green")
    for i, xi in enumerate(m0_words, 1):
        g_prev = g_trace[i-1]
        g_i    = g_trace[i]
        t.add_row(f"{i:02d}", fmt_hex(xi, 16), fmt_hex(g_prev, 16), fmt_hex(g_i, 16))
    console.print(t)

def main():
    use_rich = Console is not None
    console = Console() if use_rich else None

    # ========================= 1) "Обмін K0" =========================
    if use_rich:
        console.rule("[bold green]Етап 1: обмін початковим ключем K0 (без нормування)")
    K = generate_random_1024()
    K0 = compress_1024_to_64(K)
    if use_rich:
        console.print(Panel(Text("Alice згенерувала K (1024 біт) і стиснула до K0.\n"
                                 "Відправляємо K0 Bob-у по захищеному каналу (DH/KDF у реальному житті)."),
                            title="Alice → Bob: K0", border_style="cyan"))
        kb = Table(box=ROUNDED, show_header=False); kb.add_column("k", style="bold"); kb.add_column("v")
        kb.add_row("K (hex, 256)", f"{K:0256x}")
        kb.add_row("K0 (hex)", f"{fmt_hex(K0,16)}")
        kb.add_row("K0 (dec)", str(K0))
        console.print(Panel(kb, title="Паспорт початкового ключа", border_style="cyan"))

    # ================== 2) Локальне нормування (Alice/Bob) ==================
    if use_rich:
        console.rule("[bold green]Етап 2: локальне нормування на кожній стороні")

    wA, xA, yA, zA, tA, dA, NA, dbgA = normalize_quaternion_from_k0(K0)
    GA = gamma_from_quaternion(wA, xA, yA, zA)
    wB, xB, yB, zB, tB, dB, NB, dbgB = normalize_quaternion_from_k0(K0)
    GB = gamma_from_quaternion(wB, xB, yB, zB)

    if use_rich:
        console.print(make_norm_panel("Alice", K0, wA, xA, yA, zA, tA, dA, NA, dbgA))
        console.print(make_norm_panel("Bob  ", K0, wB, xB, yB, zB, tB, dB, NB, dbgB))
        same_q = (wA, xA, yA, zA) == (wB, xB, yB, zB)
        same_G = GA == GB
        chk = Table(box=ROUNDED, show_header=False); chk.add_column("Перевірка", style="bold cyan"); chk.add_column("Результат")
        chk.add_row("q̂(Alice) == q̂(Bob)", "✅ Так" if same_q else "❌ Ні")
        chk.add_row("Γ(Alice)  == Γ(Bob)", "✅ Так" if same_G else "❌ Ні")
        console.print(Panel(chk, title="Консенсус на обох сторонах", border_style="yellow"))
        console.print(Panel(make_matrix_table("Γ(q̂) (спільна)", GA), title="Матриця обертання", border_style="cyan"))
        console.print(Panel(make_matrix_table("Γᵀ · Γ", matmul3(transpose3(GA), GA)),
                            title=f"Перевірка ортогональності: [{'green bold'}OK{'/green bold'}]" if is_identity_mod_p(matmul3(transpose3(GA), GA)) else
                                  f"Перевірка ортогональності: [{'red bold'}FAIL{'/red bold'}]",
                            border_style="cyan"))
    else:
        print("K0:", fmt_hex(K0,16))
        print("Alice q̂:", (wA,xA,yA,zA))
        print("Bob   q̂:", (wB,xB,yB,zB))
        print("Γ equal:", GA == GB)

    # спільні параметри
    Gamma = GA  # = GB

    # ================== 3) Одне повідомлення ==================
    while True:
        if use_rich:
            console.rule("[bold yellow]Нове повідомлення")
            msg = Prompt.ask("Введіть повідомлення (UTF-8) або ENTER для виходу", default="")
        else:
            msg = input("Введіть повідомлення (UTF-8) або порожньо для виходу: ")
        if msg == "":
            if use_rich: console.print(Rule("[bold magenta]Завершення сеансу. Дякую!"))
            else: print("Завершення сеансу. Дякую!")
            break

        msg_bytes = msg.encode("utf-8")
        if use_rich:
            info = Table(box=ROUNDED, show_header=False); info.add_column("k", style="bold"); info.add_column("v")
            info.add_row("Довжина (байт)", str(len(msg_bytes)))
            console.print(Panel(info, title="Параметри повідомлення", border_style="yellow"))

        # --- M0 та перетворення матрицею ---
        M0, rest, M0_bytes18 = pack_M0_from_text(msg_bytes)   # 18 байт для М0 (нуль-доповнення, без ISO)
        C0 = matmul3(Gamma, M0)
        if use_rich:
            console.print(Panel(make_matrix_table("M0", M0), title="M0 (перші 18 байт)", border_style="blue"))
            console.print(Panel(make_matrix_table("C0 = Γ·M0", C0), title="C0 (зашифрований матричний блок)", border_style="blue"))

        # --- ОДНА сіль на весь ланцюг (Alice і Bob мають однаково бачити її) ---
        mac_salt_b64 = generate_salt(8)

        # --- Ланцюг гами БЕЗ падингу: спочатку M0, потім решта ---
        g_final, g_trace = gamma_chain_no_pad(K0, M0_bytes18, rest, mac_salt_b64)

        # --- Потокова частина ШИФРУ для «решти»: стартуємо з g після M0 ---
        g_prev = g_trace[3] if len(g_trace) >= 4 else g_trace[-1]
        X = pack_u64_stream_no_pad(rest)
        g_vals: List[int] = [g_prev]
        C_stream: List[int] = []
        for xi in X:
            gi_1 = g_vals[-1]
            ci = (xi ^ gi_1) & MASK64
            C_stream.append(ci)
            gi = g_next(xi, gi_1)
            g_vals.append(gi)

        mac = int(g_final & MASK64)

        # --- Вивід ---
        if use_rich:
            if X:
                console.print(Panel(make_words64_table("X (потокові 64-бітні слова, no-pad)", X),
                                    title="Потокова частина — відкритий текст", border_style="magenta"))
                print_stream_steps(console, X, C_stream, [g_trace[3]] + g_vals[1:] if len(g_trace) >= 4 else g_vals)
                console.print(Panel(make_words64_table("C_stream (шифротекстові блоки)", C_stream),
                                    title="Потокова частина — шифротекст", border_style="magenta"))
            else:
                # НОВЕ: немає «решти» — покажемо кроки формування гами саме для M0
                m0_words = m0_words_no_pad(M0_bytes18)
                console.print(Panel("[dim]Решти немає — потокова частина відсутня. Нижче кроки для M₀.[/dim]",
                                    title="Примітка", border_style="magenta"))
                print_gamma_steps_for_m0(console, m0_words, g_trace)

            console.print(Panel(Text(f"MAC = final g  =  {fmt_hex(mac,16)}  ({mac})",
                                     style="bold green" if mac != 0 else "bold red"),
                                title="MAC (Alice)", border_style="green"))

        # ---- Bob: розшифрування + MAC ----
        if use_rich:
            console.rule("[bold cyan]Аліса → Боб  |  Боб: розшифрування")

        # відновити M0: Γᵀ·C0
        M0_dec = matmul3(transpose3(Gamma), C0)
        first18 = unpack_M0_to_bytes(M0_dec)

        # відтворити g після M0
        g_after_m0_bob = gamma_chain_no_pad(K0, first18, b"", mac_salt_b64)[1][-1]

        # розшифрувати потік
        X_dec: List[int] = []
        g_prev_b = g_after_m0_bob
        for ci in C_stream:
            xi = (int(ci) ^ g_prev_b) & MASK64
            X_dec.append(xi)
            g_prev_b = g_next(xi, g_prev_b)

        rest_bytes = unpack_u64_stream_to_bytes(X_dec)

        # перевірити MAC: повний ланцюг
        mac_check, _ = gamma_chain_no_pad(K0, first18, rest_bytes, mac_salt_b64)
        ok_mac = (mac_check & MASK64) == (mac & MASK64)

        if use_rich:
            console.print(Panel(make_matrix_table("M0 (відновлена)", M0_dec),
                                title="Дешифрування матричного блоку", border_style="cyan"))
            mt = Table(box=ROUNDED, title="MAC порівняння")
            mt.add_column("Сторона", style="bold cyan"); mt.add_column("MAC (hex)", style="magenta"); mt.add_column("MAC (dec)")
            mt.add_row("Alice", fmt_hex(mac,16), str(mac))
            mt.add_row("Bob  ", fmt_hex(int(mac_check & MASK64),16), str(int(mac_check & MASK64)))
            console.print(Panel(mt,
                                title=f"MAC перевірка: [{'green bold'}OK{'/green bold'}]" if ok_mac else
                                      f"MAC перевірка: [{'red bold'}FAIL{'/red bold'}]",
                                border_style="green"))

        # Збирання тексту та порівняння
        recovered = (first18 + rest_bytes)[:len(msg_bytes)]
        try:
            recovered_text = recovered.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            recovered_text = recovered.decode("utf-8", errors="replace")

        same = (recovered_text == msg) and ok_mac
        if use_rich:
            out = Table.grid(); out.add_column(justify="right", style="bold"); out.add_column()
            out.add_row("Оригінал:", msg); out.add_row("Розкрито:", recovered_text)
            console.print(Panel(out,
                                title=f"Рівність повідомлень: [{'green bold'}ТАК{'/green bold'}]" if same else
                                      f"Рівність повідомлень: [{'red bold'}НІ{'/red bold'}]",
                                border_style="bright_white"))
        else:
            print("MAC OK:", ok_mac, "| same text:", same)

        if use_rich: console.rule()

if __name__ == "__main__":
    main()
