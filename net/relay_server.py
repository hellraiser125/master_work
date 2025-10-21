import asyncio
import json
from contextlib import suppress

HOST = "127.0.0.1"
PORT = 8765

clients: set[asyncio.StreamWriter] = set()

# Кеш останнього hello, щоб другий підключений гарантовано отримав nonce
last_hello_payload: dict | None = None


async def send_safe(writer: asyncio.StreamWriter, payload: dict) -> bool:
    """Надіслати payload одному клієнтові; повертає False якщо помилка."""
    try:
        msg = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
        writer.write(msg)
        await writer.drain()
        return True
    except Exception:
        return False


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    global last_hello_payload
    addr = writer.get_extra_info("peername")
    print("[RELAY] client connected:", addr)
    clients.add(writer)

    # Якщо вже є hello від іншого — одразу віддай новачку
    if last_hello_payload is not None:
        await send_safe(writer, last_hello_payload)

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
                print("[RELAY] got hello from", addr)
                last_hello_payload = obj  # кешуємо
                # розсилаємо hello всім, крім відправника
                for w in list(clients):
                    if w is writer:
                        continue
                    ok = await send_safe(w, obj)
                    if not ok:
                        with suppress(Exception):
                            clients.remove(w)
                            w.close()
                continue

            if t == "dh_params":
                print("[RELAY] got dh_params from", addr)
            elif t == "dh_pub":
                print("[RELAY] got dh_pub from", addr)
            elif t == "msg":
                print("[RELAY] got msg from", addr)

            # Розсилаємо всім іншим
            for w in list(clients):
                if w is writer:
                    continue
                ok = await send_safe(w, obj)
                if not ok:
                    with suppress(Exception):
                        clients.remove(w)
                        w.close()
    finally:
        with suppress(Exception):
            clients.remove(writer)
        with suppress(Exception):
            writer.close()


async def main():
    server = await asyncio.start_server(handle, HOST, PORT)
    print(f"Relay listening on {HOST}:{PORT}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
