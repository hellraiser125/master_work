import asyncio
import json
import os
import secrets
import base64
from typing import Callable, Optional, Dict, Any, List

from dotenv import load_dotenv
load_dotenv()
CHAT_DEBUG = os.getenv("CHAT_DEBUG", "0") == "1"

from net.secure_session import SecureSession


# ─── base64 helpers ─────────────────────────────────────────────────────────
def _b64s(data: bytes | bytearray) -> str:
    return base64.b64encode(bytes(data)).decode("ascii")


# ─── dict з доступом через атрибути ─────────────────────────────────────────
class AttrDict(dict):
    """dict з доступом через атрибути: obj['C0'] і obj.C0 — одне й те саме."""
    __slots__ = ()

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as e:
            raise AttributeError(name) from e

    def __setattr__(self, name, value):
        self[name] = value


# ─── jsonable <-> python ────────────────────────────────────────────────────
def _to_jsonable(x: Any) -> Any:
    """Перетворення у JSON-безпечну форму (на відправці)."""
    if isinstance(x, (bytes, bytearray)):
        return _b64s(x)
    if isinstance(x, (str, int, float, bool)) or x is None:
        return x
    try:
        import numpy
        if isinstance(x, numpy.integer):
            return int(x)
        if isinstance(x, numpy.floating):
            return float(x)
        if isinstance(x, numpy.ndarray):
            return [_to_jsonable(i) for i in x.tolist()]
    except Exception:
        pass
    if isinstance(x, dict):
        return {str(k): _to_jsonable(v) for k, v in x.items()}
    if isinstance(x, (list, tuple, set)):
        return [_to_jsonable(i) for i in x]
    if hasattr(x, "__dict__"):
        return {k: _to_jsonable(v) for k, v in vars(x).items()}
    return str(x)


def _from_jsonable(x: Any) -> Any:
    """ЗВОРОТНЄ перетворення (на прийомі)."""
    if isinstance(x, list):
        return [_from_jsonable(i) for i in x]
    if isinstance(x, tuple):
        return tuple(_from_jsonable(i) for i in x)
    if isinstance(x, dict):
        return AttrDict({k: _from_jsonable(v) for k, v in x.items()})
    return x


# ────────────────────────────────────────────────────────────────────────────
# NetClient
# ────────────────────────────────────────────────────────────────────────────
class NetClient:
    """
    hello ↔ hello
    min(nonce) => LEADER -> dh_params{p,g}
    обидва: gen_dh_keys(); dh_pub{pub}
    після отримання peer_pub: finalize_handshake => READY
    msg: {"type":"msg","ct": <jsonable>}
    """

    def __init__(self, host: str, port: int, on_plain_rx: Optional[Callable[[str], None]] = None):
        self.host = host
        self.port = port
        self.on_plain_rx = on_plain_rx

        self.sess = SecureSession()
        self.reader: asyncio.StreamReader = None  # type: ignore
        self.writer: asyncio.StreamWriter = None  # type: ignore

        self.my_nonce = secrets.randbits(64)
        self.peer_nonce: Optional[int] = None
        self.is_leader: Optional[bool] = None

        self.params_set = False
        self.params_id: Optional[tuple[int, int]] = None
        self._params_from_fallback = False

        self.my_pub_sent = False
        self.my_pub_value: Optional[int] = None
        self.peer_pub_value: Optional[int] = None

        self.finalized = False
        self.ready = asyncio.Event()
        self._stop = False
        self._hello_timeout_task: Optional[asyncio.Task] = None

        self._pending_msgs: List[Any] = []

    # ── lifecycle ───────────────────────────────────────────────────────────
    async def connect(self) -> None:
        if CHAT_DEBUG:
            print(f"[NET] connecting to {self.host}:{self.port} …")
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        if CHAT_DEBUG:
            print("[NET] connected; sending hello")
        await self._send({"type": "hello", "nonce": str(self.my_nonce)})

        self._hello_timeout_task = asyncio.create_task(self._hello_fallback(1.8))
        asyncio.create_task(self._reader_loop())

    def close(self) -> None:
        self._stop = True
        if self.writer:
            try:
                self.writer.close()
            except Exception:
                pass

    # ── io ──────────────────────────────────────────────────────────────────
    async def _send(self, obj: Dict[str, Any]) -> None:
        if not self.writer:
            if CHAT_DEBUG:
                print("[NET] writer is None — drop send")
            return
        payload = _to_jsonable(obj)
        data = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
        if CHAT_DEBUG:
            print(f"[NET] writing {len(data)} bytes ({obj.get('type')}) …")
        self.writer.write(data)
        await self.writer.drain()
        if CHAT_DEBUG:
            print(f"[NET] wrote {len(data)} bytes ({obj.get('type')})")

    async def _reader_loop(self) -> None:
        if CHAT_DEBUG:
            print("[NET] reader loop started")
        while not self._stop:
            line = await self.reader.readline()
            if not line:
                break
            if CHAT_DEBUG:
                print(f"[NET] read {len(line)} bytes")
            try:
                obj = json.loads(line.decode("utf-8"))
            except Exception as e:
                if CHAT_DEBUG:
                    print("[NET] json decode error:", e)
                continue
            await self._handle(obj)

    # ── hello fallback ──────────────────────────────────────────────────────
    async def _hello_fallback(self, delay: float):
        try:
            await asyncio.sleep(delay)
            if self.is_leader is None:
                self.is_leader = True
                if CHAT_DEBUG:
                    print("[ROLE] fallback: LEADER (no peer hello in time)")
            if self.is_leader and not self.params_set:
                p, g = self.sess.local_init_params()
                if CHAT_DEBUG:
                    print("[PARAMS] fallback: sending p,g")
                await self._send({"type": "dh_params", "p": str(p), "g": str(g)})
                self._apply_params_local(p, g, from_fallback=True)
                await self._maybe_send_dh_pub()
        except asyncio.CancelledError:
            pass

    # ── handler ────────────────────────────────────────────────────────────
    async def _handle(self, obj: Dict[str, Any]) -> None:
        t = obj.get("type")

        if t == "hello":
            nonce = int(obj["nonce"])
            self.peer_nonce = nonce
            if CHAT_DEBUG:
                print(f"[HELLO] peer nonce = {nonce}")
            if self._hello_timeout_task and not self._hello_timeout_task.done():
                self._hello_timeout_task.cancel()
            await self._maybe_decide_role_and_kickoff()
            return

        if t == "dh_params":
            p = int(obj["p"])
            g = int(obj["g"])
            if self.is_leader:
                if CHAT_DEBUG:
                    print("[PARAMS] ignore peer p,g (I'm LEADER)")
                return
            if self.params_set and self.params_id == (p, g):
                if CHAT_DEBUG:
                    print("[PARAMS] duplicate p,g — ignored")
                return
            if self.finalized:
                if CHAT_DEBUG:
                    print("[PARAMS] received after READY — ignored")
                return
            if CHAT_DEBUG:
                print("[PARAMS] received p,g")
            self._apply_params_remote(p, g)
            await self._maybe_send_dh_pub()
            return

        if t == "dh_pub":
            peer_pub = int(obj["pub"])
            if self.peer_pub_value == peer_pub:
                if CHAT_DEBUG:
                    print("[DH] duplicate peer pub — ignored")
                return
            if CHAT_DEBUG:
                print(f"[DH] received peer pub = {peer_pub}")
            self.peer_pub_value = peer_pub
            await self._maybe_send_dh_pub()

            if self.params_set and not self.finalized:
                self.sess.finalize_handshake(peer_pub)
                self.finalized = True
                self.ready.set()
                if CHAT_DEBUG:
                    print("[READY] session ready (K0/Γ)")

                # розшифруємо буфер до READY
                while self._pending_msgs:
                    msg = self._pending_msgs.pop(0)
                    await self._decrypt_and_deliver(msg)
            return

        if t == "msg":
            if not self.ready.is_set():
                self._pending_msgs.append(obj)
                if CHAT_DEBUG:
                    print(f"[RECV] msg before ready — buffered ({len(self._pending_msgs)})")
                return
            if CHAT_DEBUG:
                print("[RECV] msg from relay")
            await self._decrypt_and_deliver(obj)
            return

        if CHAT_DEBUG:
            print("[NET] unknown type:", t)

    # ── helpers ────────────────────────────────────────────────────────────
    async def _maybe_decide_role_and_kickoff(self) -> None:
        if self.peer_nonce is None:
            return
        became_leader = (self.my_nonce < self.peer_nonce)
        if self.is_leader is None or self.is_leader != became_leader:
            self.is_leader = became_leader
            if CHAT_DEBUG:
                print(f"[ROLE] {'LEADER' if self.is_leader else 'FOLLOWER'} decided")

        if (not self.is_leader) and self._params_from_fallback:
            if CHAT_DEBUG:
                print("[ROLE] switching from fallback-LEADER to FOLLOWER: drop local p,g")
            self.params_set = False
            self.params_id = None
            self.my_pub_sent = False
            self.my_pub_value = None
            self.peer_pub_value = None
            self.finalized = False
            self.ready.clear()
            self._params_from_fallback = False

        if self.is_leader and not self.params_set:
            p, g = self.sess.local_init_params()
            if CHAT_DEBUG:
                print("[PARAMS] sending p,g")
            await self._send({"type": "dh_params", "p": str(p), "g": str(g)})
            self._apply_params_local(p, g, from_fallback=False)
            await self._maybe_send_dh_pub()

    def _apply_params_local(self, p: int, g: int, from_fallback: bool):
        self.sess.set_dh_params(p, g)
        self.params_set = True
        self.params_id = (p, g)
        self._params_from_fallback = from_fallback
        self.my_pub_sent = False
        self.my_pub_value = None
        self.peer_pub_value = None
        self.finalized = False
        self.ready.clear()

    def _apply_params_remote(self, p: int, g: int):
        if self._params_from_fallback and CHAT_DEBUG:
            print("[ROLE] switching: drop fallback params; follow leader's p,g")
        self._apply_params_local(p, g, from_fallback=False)

    async def _maybe_send_dh_pub(self) -> None:
        if not self.params_set:
            return
        if self.my_pub_sent and self.my_pub_value is not None:
            return
        A = self.sess.gen_dh_keys()
        self.my_pub_value = A
        if CHAT_DEBUG:
            print(f"[DH] sending my pub = {A}")
        await self._send({"type": "dh_pub", "pub": str(A)})
        self.my_pub_sent = True

    # ── crypto & GUI delivery ──────────────────────────────────────────────
    async def _decrypt_and_deliver(self, obj: Dict[str, Any]) -> None:
        ct_jsonable = obj.get("ct")
        if ct_jsonable is None:
            return
        ct_obj = _from_jsonable(ct_jsonable)
        try:
            plain = self.sess.decrypt_text(ct_obj)
            if CHAT_DEBUG:
                print(f"[DECRYPTED] {plain!r}")
            # ✅ передаємо розшифроване повідомлення у GUI
            if self.on_plain_rx:
                self.on_plain_rx(str(plain))
        except Exception as e:
            err = f"[DECRYPT ERROR] {e}"
            if CHAT_DEBUG:
                print(err)
            if self.on_plain_rx:
                self.on_plain_rx(err)

    # ── API ────────────────────────────────────────────────────────────────
    async def send_plain(self, text: str) -> None:
        await self.ready.wait()
        ct_obj = self.sess.encrypt_text(text)
        ct_jsonable = _to_jsonable(ct_obj)
        if CHAT_DEBUG:
            print("[SEND] msg -> relay")
        await self._send({"type": "msg", "ct": ct_jsonable})
