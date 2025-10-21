# net/secure_session.py
from __future__ import annotations

import os
import hashlib
from dataclasses import dataclass
from typing import List, Tuple, Dict, Any, Optional

from dotenv import load_dotenv
load_dotenv()
CHAT_DEBUG = os.getenv("CHAT_DEBUG", "0") == "1"

# беремо DH та генератор ПРЯМО з твого generator.py
from crypto.generator import PrimeAndGenerator  # містить P,G та перевірку простоти :contentReference[oaicite:2]{index=2}

# шифр — як і був
from crypto.matrix_stream_cipher import (
    compress_1024_to_64,
    normalize_quaternion_from_k0,
    gamma_from_quaternion,
    encrypt as enc_core,
    decrypt as dec_core,
    # нижче — тільки для DEBUG-виводу (як у демо)
    pack_M0_from_text, unpack_M0_to_bytes,
    pack_u64_stream_no_pad, unpack_u64_stream_to_bytes,
    matmul3, transpose3, g_next, MASK64,
    gamma_chain_no_pad, m0_words_no_pad,
)

# опціональні красоти (як у демо); якщо немає — працюємо без них
try:
    from helpers.debug_views import (
        Console, Panel, Text, ROUNDED, SIMPLE_HEAVY,
        make_matrix_table, make_words64_table, make_norm_panel,
        print_stream_steps, print_gamma_steps_for_m0, fmt_hex, is_identity_mod_p
    )
except Exception:
    Console = None
    def fmt_hex(x,w=16): return f"0x{x:0{w}x}"
    def is_identity_mod_p(_): return True
    def make_matrix_table(*a,**k): return str(a[1] if len(a)>1 else "")
    def make_words64_table(*a,**k): return str(a[1] if len(a)>1 else "")

# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DHState:
    priv: int
    pub: int

def _kdf_shared_1024(shared_int: int, p_bits: int) -> bytes:
    """
    Вирівнюємо спільну таємницю до байтної довжини та детерміновано витягуємо 1024 біти
    через два SHA-512 (контр-режим), як у твоєму файлі. :contentReference[oaicite:3]{index=3}
    """
    s_bytes = shared_int.to_bytes((p_bits + 7)//8, "big") or b"\x00"
    h1 = hashlib.sha512(b"\x00" + s_bytes).digest()
    h2 = hashlib.sha512(b"\x01" + s_bytes).digest()
    return (h1 + h2)[:128]  # 1024 біти

class SecureSession:
    """
    Узгоджені по мережі P,G → DH(a,A),(b,B) → shared → 1024b → K0 → q̂ → Γ → шифр.
    P,G беремо з PrimeAndGenerator (твій generator.py), але лідер розсилає їх другому.
    """

    def __init__(self) -> None:
        self.console = Console() if CHAT_DEBUG and Console is not None else None

        # DH-параметри (ставляться іззовні через set_dh_params або local_init_params)
        self.P: Optional[int] = None
        self.G: Optional[int] = None

        # стан DH
        self.dh: Optional[DHState] = None

        # сесійні параметри шифру
        self.K0: Optional[int] = None
        self.Gamma: Optional[List[List[int]]] = None

        # для DEBUG-панелей
        self._norm_dbg: Optional[Dict[str,Any]] = None

    # ---- параметри DH -------------------------------------------------------
    def local_init_params(self) -> Tuple[int,int]:
        """
        Локально згенерувати (P,G) через твій PrimeAndGenerator (але це використаємо ТІЛЬКИ у лідера).
        :contentReference[oaicite:4]{index=4}
        """
        pg = PrimeAndGenerator()
        self.P, self.G = int(pg.get_prime()), int(pg.get_generator())
        if self.console:
            self.console.rule("[bold green]DH: локально згенеровані параметри (кандидат)")
            self.console.print(f"p = {self.P}")
            self.console.print(f"g = {self.G}")
        return self.P, self.G

    def set_dh_params(self, p: int, g: int) -> None:
        """Прийняти параметри DH від лідера."""
        self.P, self.G = int(p), int(g)
        if self.console:
            self.console.rule("[bold green]DH: встановлено параметри з мережі")
            self.console.print(f"p = {self.P}")
            self.console.print(f"g = {self.G}")

    # ---- ключі DH -----------------------------------------------------------
    def gen_dh_keys(self) -> int:
        assert self.P is not None and self.G is not None, "P,G not set"
        # приватний беремо достатньо довгий (≈256 біт), для демо достатньо
        import secrets
        a = secrets.randbits(256) or 1
        A = pow(self.G, a, self.P)
        self.dh = DHState(priv=a, pub=A)
        if self.console:
            self.console.rule("[bold green]DH: створення ключів")
            self.console.print(f"[DH] a (priv) = {a}")
            self.console.print(f"[DH] A = g^a mod p = {A}")
        return A

    def my_pub(self) -> int:
        assert self.dh is not None, "DH not initialized"
        return self.dh.pub

    # ---- завершення рукостискання ------------------------------------------
    def finalize_handshake(self, peer_pub: int) -> None:
        """
        Маємо P,G,a,A та B (peer_pub). Рахуємо shared → 1024b → K0 → q̂ → Γ.
        Рівно як у твоєму існуючому коді. :contentReference[oaicite:5]{index=5}
        """
        assert self.P is not None and self.G is not None and self.dh is not None
        if self.console:
            self.console.rule("[bold green]DH: обчислення спільної таємниці")
            self.console.print(f"[DH] peer_pub = {peer_pub}")

        s_int = pow(int(peer_pub), self.dh.priv, self.P)  # shared = B^a mod p
        shared_1024 = _kdf_shared_1024(s_int, self.P.bit_length())  # 1024b як у твоєму KDF :contentReference[oaicite:6]{index=6}

        K0 = compress_1024_to_64(int.from_bytes(shared_1024, "big"))
        w, x, y, z, t, delta_z, N_before, norm_dbg = normalize_quaternion_from_k0(K0)
        Gamma = gamma_from_quaternion(w, x, y, z)

        self.K0, self.Gamma = int(K0), Gamma
        self._norm_dbg = norm_dbg

        if self.console:
            self.console.rule("[bold green]K0 та локальне нормування")
            self.console.print(f"K0 = {fmt_hex(self.K0,16)} ({self.K0})")
            try:
                self.console.print(make_norm_panel("client", self.K0, w, x, y, z, t, delta_z, N_before, norm_dbg))
                GtG = matmul3(transpose3(Gamma), Gamma)
                ok = is_identity_mod_p(GtG)
                self.console.print(Panel(make_matrix_table("Γ(q̂) (спільна)", Gamma),
                                         title="Матриця обертання", border_style="cyan"))
                self.console.print(Panel(make_matrix_table("Γᵀ·Γ", GtG),
                                         title=f"Ортогональність: {'OK' if ok else 'FAIL'}", border_style="yellow"))
            except Exception:
                pass

    # ---- API шифру ----------------------------------------------------------
    def encrypt_text(self, text: str) -> Dict[str,Any]:
        assert self.K0 is not None and self.Gamma is not None, "No session"
        return enc_core(text, self.K0, self.Gamma)

    def decrypt_text(self, ct_obj: Dict[str,Any]) -> str:
        assert self.K0 is not None and self.Gamma is not None, "No session"
        out = dec_core(ct_obj, self.K0, self.Gamma)
        if isinstance(out, (bytes, bytearray)):
            try:    return bytes(out).decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                    return bytes(out).decode("utf-8", errors="replace")
        return out
