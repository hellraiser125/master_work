# net/relay_server.py
# Прозорий ретранслятор + "директорія" публічних ключів підпису (за hello).
# Передає JSON рядками (LF) і не втручається в протокол рукостискання.

import asyncio
import json
from typing import Dict, Optional
import os

HOST = os.getenv("HOST", "26.228.177.167")
PORT = int(os.getenv("PORT", "8765"))


class ClientState:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.id: Optional[str] = None
        self.peer_id: Optional[str] = None

    async def send(self, obj: dict):
        line = json.dumps(obj, separators=(",", ":")).encode("utf-8") + b"\n"
        self.writer.write(line)
        await self.writer.drain()


class Relay:
    def __init__(self):
        # "Директорія": id -> Ed25519 pub (base64)
        self.directory: Dict[str, str] = {}
        # Активні клієнти: id -> ClientState
        self.clients: Dict[str, ClientState] = {}
        self.status: Dict[str, str] = {}  # id -> "idle" | "busy"

    # >>> додано: універсальні хелпери відправки (використовуються нижче)
    async def _send(self, st: ClientState, obj: dict):
        await st.send(obj)

    async def _raw_send(self, st: ClientState, obj: dict):
        await st.send(obj)
    # <<<

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        st = ClientState(reader, writer)
        peername = writer.get_extra_info("peername")
        print(f"[Relay] new connection from {peername}")

        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                try:
                    obj = json.loads(line.decode("utf-8"))
                except Exception:
                    continue

                t = obj.get("type")
                if t == "hello":
                    st.id = obj["id"]
                    st.peer_id = obj.get("peer")
                    self.directory[st.id] = obj["sig_pub"]
                    self.clients[st.id] = st
                    self.status.setdefault(st.id, "idle")
                    is_chat_client = bool(obj.get("sig_pub"))
                    peer_id = obj.get("peer")
                    if is_chat_client and peer_id:
                        self.status[st.id] = "busy"
                        # якщо peer уже підключений (теж чат), позначимо й його busy
                        if peer_id in self.clients:
                            self.status[peer_id] = "busy"
                    print(f"[Relay] HELLO from {st.id}, wants {st.peer_id}")

                    # відразу повертаємо роль і, якщо відомо, публічний ключ піра
                    peer_pub = self.directory.get(st.peer_id)
                    role = "leader" if st.peer_id and st.id < st.peer_id else "follower"
                    await st.send({"type": "hello_ok", "role": role, "peer_sig_pub": peer_pub})

                    # якщо peer онлайн — повідомимо його про новий ключ
                    peer = self.clients.get(st.peer_id)
                    if peer:
                        await peer.send({"type": "peer_update", "id": st.id, "sig_pub": self.directory[st.id]})

                elif t in ("dh1", "dh2", "confirm", "msg"):
                    to_id = obj.get("to")
                    if not to_id:
                        continue
                    if t == "dh1":
                        self.status[obj.get("id")] = "busy"
                        self.status[to_id] = "busy"
                    dst = self.clients.get(to_id)
                    if dst:
                        await dst.send(obj)

                elif t == "list":
                    arr = [{"id": uid, "status": self.status.get(uid, "idle")}
                           for uid in self.clients.keys()]
                    await self._send(st, {"type": "list_ok", "online": arr})

                elif t == "status":
                    val = obj.get("value")
                    if st.id and val in ("idle", "busy"):
                        self.status[st.id] = val
                        await self._send(st, {"type": "status_ok", "value": val})
                    else:
                        await self._send(st, {"type": "error", "reason": "bad_status"})

                elif t == "invite":
                    to_id = obj.get("to")
                    if not to_id or to_id not in self.clients:
                        await self._send(st, {"type": "invite_fail", "reason": "offline"})
                    elif self.status.get(to_id, "idle") == "busy":
                        await self._send(st, {"type": "invite_fail", "reason": "busy"})
                    else:
                        # просто форвардимо запит адресату
                        await self._raw_send(self.clients[to_id], {"type": "invite", "from": st.id})
                        await self._send(st, {"type": "invite_ok"})

                elif t == "invite_reply":
                    to_id = obj.get("to")          # ініціатор
                    ok = bool(obj.get("ok"))
                    if to_id in self.clients:
                        await self._raw_send(self.clients[to_id], {"type": "invite_reply", "from": st.id, "ok": ok})
                        if ok:
                            self.status[st.id] = "busy"
                            self.status[to_id] = "busy"
                            # ГАРАНТОВАНИЙ старт для обох
                            await self._raw_send(self.clients[to_id], {"type": "start", "peer": st.id})
                            await self._raw_send(self.clients[st.id], {"type": "start", "peer": to_id})
                        await self._send(st, {"type": "invite_reply_ok"})
                    else:
                        await self._send(st, {"type": "invite_reply_fail", "reason": "offline"})

                elif t == "bye":
                    if st.id:
                        self.status[st.id] = "idle"
                    await self._send(st, {"type": "bye_ok"})
                    break

                else:
                    # невідомі службові типи ігноруємо
                    pass

        except Exception as e:
            print(f"[Relay] error: {e}")
        finally:
            if st.id and self.clients.get(st.id) is st:
                del self.clients[st.id]
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            print(f"[Relay] connection closed: {peername}")


async def main():
    relay = Relay()
    server = await asyncio.start_server(relay.handle, HOST, PORT)
    print(f"[Relay] listening on {HOST}:{PORT}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
