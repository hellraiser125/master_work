# net/net_client.py
# Клієнт: під’єднується до реле, виконує автентифікований DH (кроки 1–9),
# після READY шифрує/дешифрує повідомлення через твій Γ(q̂)-алгоритм.

import asyncio
import json
import os
from typing import Callable, Optional

from net.secure_session import (
    SecureSession, load_or_create_ed25519, ed_pub_from_b64, ed_pub_to_b64, b64e
)

HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8765"))
MY_ID = os.getenv("MY_ID", "A")
PEER_ID = os.getenv("PEER_ID", "B")
KEY_PATH = os.getenv("SIG_PRIV_PATH", f"{MY_ID}_ed25519.pem")


class NetClient:
    def __init__(self, host: str, port: int, on_plain_rx: Optional[Callable[[str], None]] = None):
        self.host = host
        self.port = port
        self.on_plain_rx = on_plain_rx or (lambda s: None)
        self.reader: asyncio.StreamReader
        self.writer: asyncio.StreamWriter

        self.sig_priv, self.sig_pub = load_or_create_ed25519(KEY_PATH)
        self.peer_sig_pub = None  # Ed25519 піра

        self.sess: Optional[SecureSession] = None
        self.role: Optional[str] = None  # leader/follower
        self._dh1_sent = False

    # ── мережа ─────────────────────────────────────────────────────────────

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        print(f"[{MY_ID}] connected to relay {self.host}:{self.port}")

        await self._send({
            "type": "hello",
            "id": MY_ID,
            "peer": PEER_ID,
            "sig_pub": ed_pub_to_b64(self.sig_pub),
        })
        asyncio.create_task(self._recv_loop())

    async def close(self):
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass

    async def _send(self, obj: dict):
        obj["from"] = MY_ID
        line = json.dumps(obj, separators=(",", ":")).encode("utf-8") + b"\n"
        self.writer.write(line)
        await self.writer.drain()

    async def _recv_loop(self):
        while True:
            line = await self.reader.readline()
            if not line:
                print(f"[{MY_ID}] relay closed")
                break
            try:
                obj = json.loads(line.decode("utf-8"))
            except Exception as e:
                print(f"[{MY_ID}] recv json error:", e)
                continue

            try:
                await self._handle(obj)
            except Exception as e:
                print(f"[{MY_ID}] handle error:", e)
                import traceback; traceback.print_exc()

    # ── обробка ────────────────────────────────────────────────────────────

    async def _handle(self, obj: dict):
        t = obj.get("type")

        if t == "hello_ok":
            self.role = obj["role"]
            peer_pub_b64 = obj.get("peer_sig_pub")
            if peer_pub_b64:
                self.peer_sig_pub = ed_pub_from_b64(peer_pub_b64)

            print(f"[{MY_ID}] (1-2) HELLO_OK. role={self.role}, peer_pub={'yes' if self.peer_sig_pub else 'no'}")
            self.sess = SecureSession(MY_ID, PEER_ID, self.sig_priv, self.peer_sig_pub)

            if self.role == "leader" and self.peer_sig_pub and not self._dh1_sent:
                ga_b64, ra_b64, sig_b64 = self.sess.sign_dh1()
                print(f"[{MY_ID}] (3) send DH1: ga, ID(A), ID(B), SigA(...), R(A)")
                await self._send({
                    "type": "dh1",
                    "to": PEER_ID,
                    "id": MY_ID,
                    "peer": PEER_ID,
                    "ga": ga_b64,
                    "r": ra_b64,
                    "sig": sig_b64,
                })
                self._dh1_sent = True
            else:
                if self.role == "leader":
                    print(f"[{MY_ID}] waiting for peer to appear (peer_update) before sending DH1")

        elif t == "peer_update":
            if not self.peer_sig_pub:
                self.peer_sig_pub = ed_pub_from_b64(obj["sig_pub"])
                print(f"[{MY_ID}] got peer's public signature key from relay directory")

            if self.role == "leader" and self.peer_sig_pub and not self._dh1_sent:
                ga_b64, ra_b64, sig_b64 = self.sess.sign_dh1()
                print(f"[{MY_ID}] (3) send DH1 (after peer_update)")
                await self._send({
                    "type": "dh1",
                    "to": PEER_ID,
                    "id": MY_ID,
                    "peer": PEER_ID,
                    "ga": ga_b64,
                    "r": ra_b64,
                    "sig": sig_b64,
                })
                self._dh1_sent = True

        elif t == "dh1":
            # B отримує DH1, перевіряє підпис A (кроки 4–5)
            if not self.sess:
                self.sess = SecureSession(MY_ID, PEER_ID, self.sig_priv, self.peer_sig_pub)

            ok = (self.peer_sig_pub is not None) and self.sess.verify_dh1(
                from_id=obj["id"], ga_b64=obj["ga"], ra_b64=obj["r"], sig_b64=obj["sig"],
                peer_sig_pub=self.peer_sig_pub,
            )
            print(f"[{MY_ID}] (4-5) recv DH1; verify SigA -> {'OK' if ok else 'FAIL'}")
            if not ok:
                return

            # Відповідаємо DH2 (крок 6)
            gb_b64, rb_b64, sig_b64 = self.sess.sign_dh2(obj["ga"], obj["r"])
            print(f"[{MY_ID}] (6) send DH2: gb, ID(B), ID(A), SigB(...), echo R(A), R(B)")
            await self._send({
                "type": "dh2",
                "to": PEER_ID,
                "id": MY_ID,
                "peer": PEER_ID,
                "ga": obj["ga"],   # ехо ga
                "gb": gb_b64,
                "ra": obj["r"],    # ехо R(A)
                "rb": rb_b64,      # R(B)
                "sig": sig_b64,
            })

        elif t == "dh2":
            # A перевіряє DH2 (крок 7), фіналізує (8), шле confirm з R(B)
            ok = (self.peer_sig_pub is not None) and self.sess.verify_dh2(
                from_id=obj["id"],
                ga_b64=obj["ga"], gb_b64=obj["gb"],
                ra_b64=obj["ra"], rb_b64=obj["rb"],
                sig_b64=obj["sig"],
                peer_sig_pub=self.peer_sig_pub,
            )
            print(f"[{MY_ID}] (7) recv DH2; verify SigB + echoes -> {'OK' if ok else 'FAIL'}")
            if not ok:
                return

            self.sess.finalize(initiator=True)
            print(f"[{MY_ID}] (8) READY; sending confirm(RB) to B")
            await self._send({"type": "confirm", "to": PEER_ID, "rb": obj["rb"]})

        elif t == "confirm":
            # B звіряє R(B) та фіналізує (крок 9)
            if obj.get("rb") == b64e(self.sess.r_my):
                self.sess.finalize(initiator=False)
                print(f"[{MY_ID}] (9) READY; R(B)'==R(B)")
            else:
                print(f"[{MY_ID}] (9) confirm mismatch")

        elif t == "msg":
            if not self.sess or not self.sess.ready:
                print(f"[{MY_ID}] [WAIT] handshake not ready; message ignored.")
                return
            try:
                plaintext = self.sess.aead_decrypt(obj["n"], obj["c"])
            except Exception as e:
                print(f"[{MY_ID}] decrypt error: {e}")
                return
            if self.on_plain_rx:
                self.on_plain_rx(plaintext)

    # ── API для GUI ────────────────────────────────────────────────────────

    async def send_plain(self, text: str):
        if not self.sess or not self.sess.ready:
            print(f"[{MY_ID}] [WAIT] handshake not ready; message ignored.")
            return
        n_b64, c_b64 = self.sess.aead_encrypt(text)
        await self._send({"type": "msg", "to": PEER_ID, "n": n_b64, "c": c_b64})
