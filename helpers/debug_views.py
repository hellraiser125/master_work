# helpers/debug_views.py
from typing import List, Tuple

# спробуємо rich; якщо нема - друкуємо простими print
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.text import Text
    from rich.box import SIMPLE_HEAVY, ROUNDED
except Exception:
    Console = None
    Table = Panel = Rule = Text = SIMPLE_HEAVY = ROUNDED = None

from crypto.matrix_stream_cipher import P, MASK64

def fmt_hex(n: int, width: int | None = None) -> str:
    if width is None:
        return f"0x{n:x}"
    return f"0x{n:0{width}x}"

def identity3() -> List[List[int]]: return [[1,0,0],[0,1,0],[0,0,1]]

def is_identity_mod_p(M) -> bool:
    I = identity3()
    for i in range(3):
        for j in range(3):
            if M[i][j] % P != I[i][j]:
                return False
    return True

def make_matrix_table(name: str, M: List[List[int]]):
    if Console is None:
        print(f"\n[{name}] (mod {P})")
        for r in M:
            print(" ", " ".join(str(v % P).rjust(6) for v in r))
        return None
    t = Table(title=name + f"  (mod {P})", box=ROUNDED, show_header=False, pad_edge=False)
    t.add_column(justify="right", style="cyan")
    t.add_column(justify="right", style="cyan")
    t.add_column(justify="right", style="cyan")
    for row in M:
        t.add_row(*[str(v % P).rjust(6) for v in row])
    return t

def make_words64_table(title: str, arr: List[int]):
    if Console is None:
        print(f"\n[{title}]")
        if not arr: print("  <порожньо>"); return None
        for i, v in enumerate(arr, 1):
            print(f" {i:02d}. {fmt_hex(v, 16)}  {v}")
        return None
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

def make_norm_panel(side: str, K0: int, w: int, x: int, y: int, z: int, t: int, delta_z: int, N_before: int, norm_dbg: dict):
    if Console is None:
        print(f"\n[{side}] Нормування q̂, K0={fmt_hex(K0,16)}")
        print(" q_raw:", norm_dbg.get("wxyz_raw"))
        print(" Δz:", delta_z, " t:", t, " N(at Δz):", N_before)
        print(" q̂:", (w,x,y,z), " ‖q̂‖² mod 65537:", norm_dbg.get("chosen",{}).get("norm_after"))
        return None
    from rich.panel import Panel
    from rich.table import Table
    passport = Table(box=ROUNDED, show_header=False, pad_edge=False)
    passport.add_column("k", style="bold"); passport.add_column("v")
    passport.add_row("K0 (64-bit)",  f"{fmt_hex(K0,16)}  ({K0})")
    passport.add_row("q_raw (from K0)", str(norm_dbg["wxyz_raw"]))
    passport.add_row("Δz (chosen)", str(delta_z))
    passport.add_row("N (at chosen Δz)", str(N_before))
    passport.add_row("invN", str(norm_dbg["chosen"]["invN"]))
    t_alt = (P - t) % P
    passport.add_row("sqrt(invN) candidates", f"{t}, {t_alt}")
    passport.add_row("t (chosen)", str(t))
    passport.add_row("q̂ = (w,x,y,z)", f"({w}, {x}, {y}, {z})")
    passport.add_row("‖q̂‖² mod 65537", str(norm_dbg["chosen"]["norm_after"]))
    return Panel(passport, title=f"[{side}] Локальне нормування q̂", border_style="green")

def print_stream_steps(console, X: List[int], C_stream: List[int], g_vals: List[int]):
    if Console is None:
        print("\n[Кроки потокового шифру]")
        for i, xi in enumerate(X, 1):
            print(f" {i:02d}: Xi={fmt_hex(xi,16)}  g_(i-1)={fmt_hex(g_vals[i-1],16)}  "
                  f"Ci={fmt_hex(C_stream[i-1],16)}  g_i={fmt_hex(g_vals[i],16)}")
        return
    t = Table(title="Кроки потокового шифрування", box=SIMPLE_HEAVY)
    t.add_column("i", justify="right", style="bold cyan")
    t.add_column("X_i (hex)", style="magenta")
    t.add_column("g_(i-1) (hex)", style="yellow")
    t.add_column("C_i = X_i XOR g_(i-1)", style="bold white")
    t.add_column("g_i = f64(X_i, g_(i-1))", style="green")
    for i, xi in enumerate(X, 1):
        t.add_row(f"{i:02d}", fmt_hex(xi, 16), fmt_hex(g_vals[i-1], 16),
                  fmt_hex(C_stream[i-1], 16), fmt_hex(g_vals[i], 16))
    console.print(t)

def print_gamma_steps_for_m0(console, m0_words: List[int], g_trace: List[int]):
    if Console is None:
        print("\n[Кроки формування гами для M0]")
        for i, xi in enumerate(m0_words, 1):
            g_prev = g_trace[i-1]; g_i = g_trace[i]
            print(f" {i:02d}: Xi={fmt_hex(xi,16)}  g_(i-1)={fmt_hex(g_prev,16)}  g_i={fmt_hex(g_i,16)}")
        return
    t = Table(title="Кроки формування гами для M₀", box=SIMPLE_HEAVY)
    t.add_column("i", justify="right", style="bold cyan")
    t.add_column("X_i (hex)", style="magenta")
    t.add_column("g_(i-1) (hex)", style="yellow")
    t.add_column("g_i = f64(X_i, g_(i-1))", style="green")
    for i, xi in enumerate(m0_words, 1):
        g_prev = g_trace[i-1]; g_i = g_trace[i]
        t.add_row(f"{i:02d}", fmt_hex(xi, 16), fmt_hex(g_prev, 16), fmt_hex(g_i, 16))
    console.print(t)
