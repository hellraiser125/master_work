#!/usr/bin/env python3
"""
Універсальний MITM-проксі для твого relay_server.py.

Слухає PROXY_HOST:PROXY_PORT, підключається до REAL_RELAY_HOST:REAL_RELAY_PORT
і може спотворювати/дропати/повторювати пакети протоколу.

Налаштування через ENV:

  PROXY_HOST        – адреса, де слухає атакер (куди підключаються клієнти)
  PROXY_PORT        – порт атакера (де клієнти думають, що relay)

  REAL_RELAY_HOST   – реальний relay_server
  REAL_RELAY_PORT   – порт реального relay_server

  ATTACK_MODES      – список режимів через кому, напр.:
                       "flip_ga,flip_rb,corrupt_sig"
                     Доступні режими:
                       - log_only
                       - flip_ga
                       - flip_gb
                       - flip_r
                       - flip_rb
                       - corrupt_sig
                       - replay_dh1
                       - replay_dh2
                       - drop_confirm
                       - drop_msg

  DELAY_MS          – штучна затримка (мс) для ВСІХ пакетів
"""

import asyncio
import base64
import json
import os
from typing import Any, Dict, Optional, List

# ================== НАЛАШТУВАННЯ З ENV ==================

PROXY_HOST = os.getenv("PROXY_HOST", "0.0.0.0")
PROXY_PORT = int(os.getenv("PROXY_PORT", "8765"))

REAL_RELAY_HOST = os.getenv("REAL_RELAY_HOST", "127.0.0.1")
REAL_RELAY_PORT = int(os.getenv("REAL_RELAY_PORT", "8766"))

ATTACK_MODES: List[str] = [
    m.strip() for m in os.getenv("ATTACK_MODES", "log_only").split(",") if m.strip()
]

DELAY_MS = int(os.getenv("DELAY_MS", "0"))

# Для replay-атак
stored_dh1: Optional[Dict[str, Any]] = None
stored_dh2: Optional[Dict[str, Any]] = None


# ================== УТИЛІТИ ДЛЯ СПОТВОРЕННЯ ==================

def b64_flip_first_byte(b64_str: str) -> str:
    """
    Акуратно міняємо перший байт у base64-рядку, щоб він лишався валідним.
    """
    try:
        raw = base64.b64decode(b64_str)
    except Exception:
        return b64_str
    if not raw:
        return b64_str
    flipped = bytes([raw[0] ^ 0x01]) + raw[1:]
    return base64.b64encode(flipped).decode("ascii")


def maybe_delay():
    if DELAY_MS > 0:
        return asyncio.sleep(DELAY_MS / 1000.0)
    return asyncio.sleep(0)


def modes_str() -> str:
    return ", ".join(ATTACK_MODES) if ATTACK_MODES else "none"


# ================== ЛОГІКА АТАК ДЛЯ КЛІЄНТА -> RELAY ==================

def attack_client_to_server(msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Тут ми міняємо те, що йде ВІД клієнта ДО реального relay.
    Якщо повернути None – пакет буде ПРОКОВТНУТО (drop).
    """
    global stored_dh1, stored_dh2

    mtype = msg.get("type")

    # --- drop_confirm / drop_msg ---
    if "drop_confirm" in ATTACK_MODES and mtype == "confirm":
        print("[MITM] drop_confirm: confirm пакет не відправлено далі")
        return None

    if "drop_msg" in ATTACK_MODES and mtype == "msg":
        print("[MITM] drop_msg: msg пакет не відправлено далі")
        return None

    # --- replay_dh1 ---
    if "replay_dh1" in ATTACK_MODES and mtype == "dh1":
        if stored_dh1 is None:
            stored_dh1 = msg.copy()
            print("[MITM] replay_dh1: збережено перший dh1")
        else:
            print("[MITM] replay_dh1: підміняємо dh1 на збережений")
            msg = stored_dh1.copy()

    # --- replay_dh2 ---
    if "replay_dh2" in ATTACK_MODES and mtype == "dh2":
        if stored_dh2 is None:
            stored_dh2 = msg.copy()
            print("[MITM] replay_dh2: збережено перший dh2")
        else:
            print("[MITM] replay_dh2: підміняємо dh2 на збережений")
            msg = stored_dh2.copy()

    # --- flip_ga / flip_r у dh1 ---
    if mtype == "dh1":
        if "flip_ga" in ATTACK_MODES and "ga" in msg:
            old = msg["ga"]
            msg["ga"] = b64_flip_first_byte(old)
            print("[MITM] flip_ga: змінено ga в dh1")

        if "flip_r" in ATTACK_MODES and "r" in msg:
            old = msg["r"]
            msg["r"] = b64_flip_first_byte(old)
            print("[MITM] flip_r: змінено r в dh1")

    # --- flip_gb у dh2 ---
    if mtype == "dh2":
        if "flip_gb" in ATTACK_MODES and "gb" in msg:
            old = msg["gb"]
            msg["gb"] = b64_flip_first_byte(old)
            print("[MITM] flip_gb: змінено gb в dh2")

    # --- flip_rb у confirm ---
    if mtype == "confirm":
        if "flip_rb" in ATTACK_MODES and "rb" in msg:
            old = msg["rb"]
            msg["rb"] = b64_flip_first_byte(old)
            print("[MITM] flip_rb: змінено rb в confirm")

    # --- corrupt_sig у dh1/dh2 ---
    if "corrupt_sig" in ATTACK_MODES and mtype in ("dh1", "dh2"):
        if "sig" in msg:
            old = msg["sig"]
            msg["sig"] = b64_flip_first_byte(old)
            print(f"[MITM] corrupt_sig: змінено sig в {mtype}")

    return msg


# ================== ЛОГІКА АТАК ДЛЯ RELAY -> КЛІЄНТА ==================

def attack_server_to_client(msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Тут можна міняти те, що йде ВІД реального relay ДО клієнта.
    Аналогічно: якщо повернути None – пакет буде дропнутий.
    """
    mtype = msg.get("type")

    # Наприклад, можна дропнути `start` для імітації дивної поведінки:
    # if "drop_start" in ATTACK_MODES and mtype == "start":
    #     print("[MITM] drop_start: не передаємо start клієнту")
    #     return None

    # Тут поки не чіпаємо нічого – основні цікаві речі йдуть C->S.
    return msg


# ================== ПАЙПІНГ ==================

async def pipe(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    direction: str,
    attack_fn,
):
    """
    Читаємо JSON-рядки з одного боку, опціонально модифікуємо,
    відправляємо на інший бік.
    direction: "C->S" або "S->C".
    attack_fn: attack_client_to_server або attack_server_to_client.
    """
    peer = writer.get_extra_info("peername")
    try:
        while True:
            line = await reader.readline()
            if not line:
                break

            line_str = line.decode("utf-8", errors="ignore").strip()
            if not line_str:
                continue

            # Спробуємо розпарсити як JSON
            try:
                obj = json.loads(line_str)
                print(f"[{direction}] {obj}")
            except json.JSONDecodeError:
                print(f"[{direction}] not JSON: {line_str!r}")
                await maybe_delay()
                writer.write(line + b"\n")
                await writer.drain()
                continue

            # застосовуємо атаку
            attacked = attack_fn(obj)

            # dropped
            if attacked is None:
                print(f"[{direction}] DROPPED packet type={obj.get('type')}")
                continue

            await maybe_delay()
            out_line = (
                json.dumps(attacked, separators=(",", ":")) + "\n"
            ).encode("utf-8")
            writer.write(out_line)
            await writer.drain()

    except Exception as e:
        print(f"[{direction}] error: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        print(f"[{direction}] closed (peer={peer})")


async def handle_client(client_reader: asyncio.StreamReader,
                        client_writer: asyncio.StreamWriter):
    """
    Для кожного нового клієнта:
      - відкриваємо з'єднання до REAL_RELAY
      - запускаємо дві "труби": C->S та S->C
    """
    client_peer = client_writer.get_extra_info("peername")
    print(f"[MITM] new client connection from {client_peer}")

    try:
        server_reader, server_writer = await asyncio.open_connection(
            REAL_RELAY_HOST, REAL_RELAY_PORT
        )
    except Exception as e:
        print(f"[MITM] cannot connect to REAL_RELAY {REAL_RELAY_HOST}:{REAL_RELAY_PORT}: {e}")
        client_writer.close()
        await client_writer.wait_closed()
        return

    task_c2s = asyncio.create_task(
        pipe(client_reader, server_writer, "C->S", attack_client_to_server)
    )
    task_s2c = asyncio.create_task(
        pipe(server_reader, client_writer, "S->C", attack_server_to_client)
    )

    await asyncio.wait(
        [task_c2s, task_s2c],
        return_when=asyncio.FIRST_COMPLETED
    )

    try:
        client_writer.close()
        await client_writer.wait_closed()
    except Exception:
        pass
    try:
        server_writer.close()
        await server_writer.wait_closed()
    except Exception:
        pass

    print(f"[MITM] client connection closed: {client_peer}")


async def main():
    print(f"[MITM] Listening on {PROXY_HOST}:{PROXY_PORT}")
    print(f"[MITM] Real relay: {REAL_RELAY_HOST}:{REAL_RELAY_PORT}")
    print(f"[MITM] ATTACK_MODES = {modes_str()}")
    if DELAY_MS > 0:
        print(f"[MITM] DELAY_MS = {DELAY_MS} ms")

    server = await asyncio.start_server(handle_client, PROXY_HOST, PROXY_PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[MITM] stopped by user")
