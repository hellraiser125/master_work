# net/secure_session.py
# X25519-DH (ефемерний) + Ed25519 підписи для рукостискання.
# Після рукостискання: конвеєр з matrix_stream_cipher (K(1024)→K0→q̂→Γ)
# і виклики encrypt()/decrypt() з твого модуля без змін алгоритму.

import os
import json
import base64
import secrets
from dataclasses import dataclass
from typing import Optional, Tuple, Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

# ── Твій шифр ─────────────────────────────────────────────────────────────
from crypto.matrix_stream_cipher import (
    compress_1024_to_64,
    normalize_quaternion_from_k0,
    gamma_from_quaternion,
    Ciphertext,
    encrypt as dd_encrypt,
    decrypt as dd_decrypt,
)

# ── Хелпери, які імпортує net_client ─────────────────────────────────────
def load_or_create_ed25519(path_priv: str):
    """Створює або завантажує Ed25519 приватний ключ з PEM. Повертає (priv, pub)."""
    if os.path.exists(path_priv):
        with open(path_priv, "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
        if not isinstance(priv, Ed25519PrivateKey):
            raise ValueError("Wrong key type in PEM")
        return priv, priv.public_key()

    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    with open(path_priv, "wb") as f:
        f.write(pem)
    return priv, priv.public_key()

def ed_pub_to_b64(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode("ascii")

def ed_pub_from_b64(s: str) -> Ed25519PublicKey:
    raw = base64.b64decode(s.encode("ascii"))
    return Ed25519PublicKey.from_public_bytes(raw)

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

# ── Сесійні ключі ─────────────────────────────────────────────────────────
@dataclass
class SessionKeys:
    k1024_bytes: bytes  # 128 байт з HKDF
    K0_64: int          # твій K0
    Gamma: Any          # 3x3 матриця (списки списків int)

# ── Сесія ─────────────────────────────────────────────────────────────────
class SecureSession:
    """
    1) X25519 ефермерний DH
    2) Ed25519 підписи NETDH1/NETDH2 (контекст транскрипту)
    3) HKDF( shared, 128B ) → int → compress_1024_to_64 → normalize_quaternion_from_k0 → gamma_from_quaternion
    4) Поверх цього — твій encrypt()/decrypt()
    """

    def __init__(self, my_id: str, peer_id: str,
                 sig_priv: Ed25519PrivateKey,
                 peer_sig_pub: Optional[Ed25519PublicKey] = None):
        self.my_id = my_id
        self.peer_id = peer_id
        self.sig_priv = sig_priv
        self.peer_sig_pub = peer_sig_pub

        # ефермерні DH
        self.ec_priv = X25519PrivateKey.generate()
        self.ec_pub = self.ec_priv.public_key()

        # нонси для salt
        self.r_my = secrets.token_bytes(16)
        self.r_peer: Optional[bytes] = None

        # публічний X25519 піра
        self.peer_ec_pub: Optional[X25519PublicKey] = None

        self.ready = False
        self.keys: Optional[SessionKeys] = None

        # >>> запам’ятовуємо, що ми відправили в DH1 (для захисту від replay_dh1)
        self.ga_local_b64: Optional[str] = None
        self.r_local_b64: Optional[str] = None
        # <<<

    # ── контексти підпису ─────────────────────────────────────────────────
    @staticmethod
    def _ctx_dh1(ida: bytes, idb: bytes, ga: bytes, ra: bytes) -> bytes:
        return b"|".join([b"NETDH1", ida, idb, ga, ra])

    @staticmethod
    def _ctx_dh2(ida: bytes, idb: bytes, ga: bytes, gb: bytes, ra: bytes, rb: bytes) -> bytes:
        return b"|".join([b"NETDH2", ida, idb, ga, gb, ra, rb])

    # ── DH1 (A→B) ─────────────────────────────────────────────────────────
    def sign_dh1(self) -> Tuple[str, str, str]:
        """
        Викликається ініціатором (leader).
        Повертає (ga_b64, ra_b64, sig_b64) і одночасно запам'ятовує їх
        для подальшої перевірки контексту в verify_dh2 (anti-replay).
        """
        ga = self.ec_pub.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )
        ctx = self._ctx_dh1(self.my_id.encode(), self.peer_id.encode(), ga, self.r_my)
        sig = self.sig_priv.sign(ctx)

        ga_b64 = _b64e(ga)
        ra_b64 = _b64e(self.r_my)
        sig_b64 = _b64e(sig)

        # >>> зберігаємо свій ga та r для подальшої перевірки в verify_dh2
        self.ga_local_b64 = ga_b64
        self.r_local_b64 = ra_b64
        # <<<

        return ga_b64, ra_b64, sig_b64

    def verify_dh1(self, from_id: str, ga_b64: str, ra_b64: str, sig_b64: str,
                   peer_sig_pub: Ed25519PublicKey) -> bool:
        ga = _b64d(ga_b64)
        ra = _b64d(ra_b64)
        ctx = self._ctx_dh1(from_id.encode(), self.my_id.encode(), ga, ra)
        try:
            peer_sig_pub.verify(_b64d(sig_b64), ctx)
            self.peer_ec_pub = X25519PublicKey.from_public_bytes(ga)
            self.r_peer = ra
            return True
        except Exception:
            return False

    # ── DH2 (B→A) ─────────────────────────────────────────────────────────
    def sign_dh2(self, ga_b64: str, ra_b64: str) -> Tuple[str, str, str]:
        gb = self.ec_pub.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )
        ga = _b64d(ga_b64)
        ra = _b64d(ra_b64)
        ctx = self._ctx_dh2(self.peer_id.encode(), self.my_id.encode(), ga, gb, ra, self.r_my)
        sig = self.sig_priv.sign(ctx)
        return _b64e(gb), _b64e(self.r_my), _b64e(sig)

    def verify_dh2(self, from_id: str, ga_b64: str, gb_b64: str,
                   ra_b64: str, rb_b64: str, sig_b64: str,
                   peer_sig_pub: Ed25519PublicKey) -> bool:
        """
        Викликається завжди на стороні ініціатора (leader).
        Тут якраз і додаємо жорстку перевірку контексту для захисту від replay_dh1.
        """
        # >>> Anti-replay перевірка контексту (тільки якщо ми попередньо відправляли DH1)
        if self.ga_local_b64 is not None and ga_b64 != self.ga_local_b64:
            print(f"[HANDSHAKE-ERROR] DH2.ga != DH1.ga "
                  f"(expected {self.ga_local_b64}, got {ga_b64}) — можливий replay_dh1/MITM")
            return False

        if self.r_local_b64 is not None and ra_b64 != self.r_local_b64:
            print(f"[HANDSHAKE-ERROR] DH2.ra != DH1.r "
                  f"(expected {self.r_local_b64}, got {ra_b64}) — можливий replay/MITM")
            return False
        # <<<

        ga = _b64d(ga_b64)
        gb = _b64d(gb_b64)
        ra = _b64d(ra_b64)
        rb = _b64d(rb_b64)
        ctx = self._ctx_dh2(self.my_id.encode(), from_id.encode(), ga, gb, ra, rb)
        try:
            peer_sig_pub.verify(_b64d(sig_b64), ctx)
            self.peer_ec_pub = X25519PublicKey.from_public_bytes(gb)
            self.r_peer = rb
            print("[HANDSHAKE] DH2 signature OK, контекст узгоджений — replay_dh1 заблоковано.")
            return True
        except Exception:
            print("[HANDSHAKE-ERROR] sig(dh2) invalid")
            return False

    # ── Фіналізація: K(1024)→K0→q̂→Γ ─────────────────────────────────────
    def finalize(self, initiator: bool):
        if not self.peer_ec_pub or self.r_peer is None:
            raise ValueError("Handshake not complete")
        shared = self.ec_priv.exchange(self.peer_ec_pub)

        # 128 байт із HKDF → у int для твоїх функцій
        salt = (self.r_my + self.r_peer) if initiator else (self.r_peer + self.r_my)
        k1024_bytes = HKDF(
            algorithm=hashes.SHA256(),
            length=128,              # 128 bytes = 1024 bits
            salt=salt,
            info=b"NETDH-v1",
        ).derive(shared)
        k1024_int = int.from_bytes(k1024_bytes, "big")

        K0_64 = compress_1024_to_64(k1024_int)
        qhat = normalize_quaternion_from_k0(K0_64)

        # normalize_quaternion_from_k0 повертає: ŵ,x̂,ŷ,ẑ,t,delta,N,debug
        w, x, y, z = qhat[0], qhat[1], qhat[2], qhat[3]
        Gamma = gamma_from_quaternion(w, x, y, z)

        self.keys = SessionKeys(k1024_bytes, K0_64, Gamma)
        self.ready = True
        print("--------------------------------------------------")
        print(f"[{self.my_id}] SECURE SESSION FINALIZED  ✅")
        print(f"[{self.my_id}] 1024-bit → K0 = {self.keys.K0_64}")
        print(f"[{self.my_id}] quaternion = (w={w}, x={x}, y={y}, z={z})")
        print(f"[{self.my_id}] Γ(q̂) =")
        for row in Gamma:
            print(f"   {row}")
        print("--------------------------------------------------")

    # ── Обгортки над твоїм encrypt/decrypt ───────────────────────────────
    def aead_encrypt(self, plaintext: str) -> Tuple[str, str]:
        """
        Повертаємо (n, c):
          n — дублюємо salt, якщо він є в meta (для зручності дебагу),
          c — JSON серіалізація твого Ciphertext.
        """
        assert self.ready and self.keys, "Session not ready"
        ct: Ciphertext = dd_encrypt(plaintext, self.keys.K0_64, self.keys.Gamma)  # type: ignore

        # нормалізуємо у словник (щоб не тягнути dataclasses.asdict)
        c_dict = {
            "C0": ct.C0,
            "stream": [int(x) for x in ct.stream],
            "mac": int(ct.mac),
            "meta": dict(ct.meta),
        }
        c_json = json.dumps(c_dict, separators=(",", ":"))

        # витягнемо salt/nonce у поле n (опційно)
        n = c_dict["meta"].get("mac_salt_b64", "")
        return n, c_json

    def aead_decrypt(self, nonce_b64: str, ct_json: str) -> str:
        assert self.ready and self.keys, "Session not ready"
        obj = json.loads(ct_json)

        # Відновлюємо саме твій контейнер Ciphertext
        ct = Ciphertext(
            C0=obj["C0"],
            stream=[int(x) for x in obj["stream"]],
            mac=int(obj["mac"]),
            meta=obj["meta"],
        )
        pt = dd_decrypt(ct, self.keys.K0_64, self.keys.Gamma)  # type: ignore
        return pt  # decrypt повертає str
