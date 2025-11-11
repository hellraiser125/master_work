# net/relay_server.py
# Прозорий ретранслятор + "директорія" публічних ключів підпису (за hello).
# Передає JSON рядками (LF) і не втручається в протокол рукостискання.

import asyncio
import json
from typing import Dict, Optional

HOST = "127.0.0.1"
PORT = 8765


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
                    dst = self.clients.get(to_id)
                    if dst:
                        await dst.send(obj)
                else:
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
