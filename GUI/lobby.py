# GUI/lobby.py
import os
import sys
import json
import asyncio
import subprocess
from typing import Optional, List, Dict

from PySide6 import QtWidgets, QtCore

HOST = os.getenv("HOST", "26.228.177.167")
PORT = int(os.getenv("PORT", "8765"))

# ---- допоміжне: рандомний ID, якщо не задано через ENV
import random, string
def random_id(prefix="A", k=4):
    return f"{prefix}_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=k))
MY_ID = os.getenv("MY_ID") or random_id("A")

class RelayAPI(QtCore.QObject):
    """Мінімальний клієнт до реле для list/invite/invite_reply/status/start."""
    inviteReceived = QtCore.Signal(str)        # from_id
    inviteReply = QtCore.Signal(str, bool)     # from_id, ok
    listUpdated = QtCore.Signal(list)          # [{"id":..., "status":...},...]
    startRequested = QtCore.Signal(str)        # peer_id  ← NEW

    def __init__(self, host: str, port: int, my_id: str, parent=None):
        super().__init__(parent)
        self.host = host
        self.port = port
        self.my_id = my_id
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self._task = None

    async def start(self):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        await self._send({"type": "hello", "id": self.my_id, "sig_pub": ""})
        loop = asyncio.get_running_loop()
        self._task = loop.create_task(self._recv_loop())
        await self.set_status("idle")

    async def stop(self, set_idle: bool = True):
        try:
            if set_idle:
                await self._send({"type": "bye"})  # лишаємо як було
        except Exception:
            pass
        try:
            if self.writer:
                self.writer.close()
                await self.writer.wait_closed()
        except Exception:
            pass
        self.reader = None
        self.writer = None
        self._task = None

    async def _send(self, obj: dict):
        obj.setdefault("from", self.my_id)
        self.writer.write((json.dumps(obj) + "\n").encode("utf-8"))
        await self.writer.drain()

    async def _recv_loop(self):
        try:
            while True:
                line = await self.reader.readline()
                if not line:
                    return
                try:
                    msg = json.loads(line.decode("utf-8").strip())
                except Exception:
                    continue
                t = msg.get("type")
                if t == "invite":
                    self.inviteReceived.emit(msg.get("from",""))
                elif t == "invite_reply":
                    self.inviteReply.emit(msg.get("from",""), bool(msg.get("ok")))
                elif t == "list_ok":
                    self.listUpdated.emit(msg.get("online", []))
                elif t == "start":                     # ← NEW
                    self.startRequested.emit(msg.get("peer",""))
        except asyncio.CancelledError:
            pass

    async def get_list(self):
        await self._send({"type": "list"})

    async def invite(self, peer_id: str):
        await self._send({"type": "invite", "to": peer_id})

    async def reply(self, to_id: str, ok: bool):
        await self._send({"type": "invite_reply", "to": to_id, "ok": ok})

    async def set_status(self, value: str):
        await self._send({"type": "status", "value": value})

    # всередині RelayAPI
    def is_connected(self) -> bool:
        return self.writer is not None and not self.writer.is_closing()

    async def _send(self, obj: dict):
        if not self.is_connected():
            return  # тихо ігноруємо, коли з’єднання ще/вже нема
        obj.setdefault("from", self.my_id)
        self.writer.write((json.dumps(obj) + "\n").encode("utf-8"))
        await self.writer.drain()

    async def get_list(self):
        if not self.is_connected():
            return
        await self._send({"type": "list"})

    async def invite(self, peer_id: str):
        if not self.is_connected():
            return
        await self._send({"type": "invite", "to": peer_id})

    async def reply(self, to_id: str, ok: bool):
        if not self.is_connected():
            return
        await self._send({"type": "invite_reply", "to": to_id, "ok": ok})

    async def set_status(self, value: str):
        if not self.is_connected():
            return
        await self._send({"type": "status", "value": value})


class LobbyWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"Лобі — {MY_ID}")
        self.resize(480, 560)

        self.list = QtWidgets.QListWidget()
        self.btnRefresh = QtWidgets.QPushButton("Оновити список")
        self.btnInvite  = QtWidgets.QPushButton("Запросити")
        self.info = QtWidgets.QLabel(
            f"Твій ID: <b>{MY_ID}</b>\n"
            "Вибери користувача та натисни «Запросити». Очікуємо інвайт або відповідь..."
        )

        v = QtWidgets.QVBoxLayout(self)
        v.addWidget(QtWidgets.QLabel(f"Relay: {HOST}:{PORT}"))
        v.addWidget(self.list, 1)
        h = QtWidgets.QHBoxLayout()
        h.addWidget(self.btnRefresh)
        h.addWidget(self.btnInvite)
        v.addLayout(h)
        v.addWidget(self.info)

        # 1) створюємо та реєструємо окремий asyncio loop
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        # 2) СТВОРЮЄМО self.api ДО підписок на сигнали (вирішує твою помилку)
        self.api = RelayAPI(HOST, PORT, MY_ID)

        # 3) підписки на сигнали
        self.api.listUpdated.connect(self.onListUpdated)
        self.api.inviteReceived.connect(self.onInviteReceived)
        self.api.inviteReply.connect(self.onInviteReply)
        self.api.startRequested.connect(self.onStartRequested)  # ← NEW

        # кнопки/таймери створюють задачі на self.loop
        self.btnRefresh.clicked.connect(lambda: self.loop.create_task(self.api.get_list()))
        self.btnInvite.clicked.connect(self.onInvite)

        # таймер для інтеграції asyncio з Qt
        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self._iterate_loop)
        self.timer.start(15)

        # автопул списку
        self.autorefresh = QtCore.QTimer(self)
        self.autorefresh.timeout.connect(lambda: self.loop.create_task(self.api.get_list()))
        self.autorefresh.start(3000)

        # старт API на нашому loop
        self.loop.create_task(self.api.start())
        self._in_chat = False

    def _iterate_loop(self):
        self.loop.call_soon(self.loop.stop)
        self.loop.run_forever()

    def onListUpdated(self, arr: List[Dict]):
        self.list.clear()
        for it in arr:
            uid = it.get("id","")
            st  = it.get("status","idle")
            label = f"{uid}   —   {st}"
            if uid == MY_ID:
                label += "   (you)"
            self.list.addItem(label)

    def current_selected_id(self) -> Optional[str]:
        it = self.list.currentItem()
        if not it: return None
        text = it.text()
        return text.split("—")[0].strip()

    def onInvite(self):
        pid = self.current_selected_id()
        if not pid:
            QtWidgets.QMessageBox.information(self, "Лобі", "Оберіть користувача в списку.")
            return
        if pid == MY_ID:
            QtWidgets.QMessageBox.information(self, "Лобі", "Неможливо запросити самого себе 🙂")
            return
        self.loop.create_task(self.api.invite(pid))
        self.info.setText(f"Надіслано інвайт до: {pid}. Чекаємо відповідь...")

    def onInviteReceived(self, from_id: str):
        ret = QtWidgets.QMessageBox.question(self, "Вхідний запит",
                                             f"{from_id} хоче розпочати чат. Прийняти?",
                                             QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
        ok = (ret == QtWidgets.QMessageBox.Yes)
        self.loop.create_task(self.api.reply(from_id, ok))
        if ok:
            self.loop.create_task(self.api.set_status("busy"))
            self.loop.create_task(self.api.stop())
            self.start_chat(peer_id=from_id)

    def onInviteReply(self, from_id: str, ok: bool):
        if ok:
            self.loop.create_task(self.api.set_status("busy"))
            self.loop.create_task(self.api.stop())
            self.start_chat(peer_id=from_id)
        else:
            QtWidgets.QMessageBox.information(self, "Відмова", f"{from_id} відхилив запит.")
            self.info.setText("Запит відхилено. Оберіть іншого користувача.")

    # ← NEW: страховий запуск чату за командою сервера
    def onStartRequested(self, peer_id: str):
        # страховка від повторного запуску
        if getattr(self, "_in_chat", False):
            return
        self._in_chat = True
        print(f"[LOBBY {MY_ID}] start by server with peer={peer_id}")
        try:
            self.loop.create_task(self.api.set_status("busy"))
            self.loop.create_task(self.api.stop())      # звільняємо ID
            self.start_chat(peer_id=peer_id)            # відкриваємо GUI.gui
        finally:
            self._in_chat = False


    def start_chat(self, peer_id: str):
        if self.autorefresh.isActive():
            self.autorefresh.stop()
        # якщо чат уже запущений — не дублюємо
        if getattr(self, "_chat_proc", None) and self._chat_proc.poll() is None:
            return

        # 1) акуратно від’єднатись від реле, щоб GUI.gui зміг зайняти той самий MY_ID
        try:
            self.loop.run_until_complete(self.api.stop(set_idle=False))
        except Exception:
            pass

        # 2) підготувати оточення для дочірнього процесу
        env = os.environ.copy()
        env["MY_ID"] = MY_ID          # гарантуємо однаковий ID у чаті
        env["PEER_ID"] = peer_id      # з ким говоримо

        # 3) старт чату без блокування
        self.hide()
        self.info.setText(f"Встановлюємо з’єднання з {peer_id}...")
        try:
            self._chat_proc = subprocess.Popen([sys.executable, "-m", "GUI.gui"], env=env)
        except Exception as e:
            # якщо не стартануло — повертаємо лобі і presence
            self.show()
            QtWidgets.QMessageBox.critical(self, "Помилка запуску чату", str(e))
            self.loop.create_task(self.api.start())
            self.loop.create_task(self.api.set_status("idle"))
            self.loop.create_task(self.api.get_list())
            return

        # 4) таймер-вотчер: перевіряємо, чи закрився чат
        if not hasattr(self, "_chat_watch"):
            self._chat_watch = QtCore.QTimer(self)
            self._chat_watch.setInterval(500)  # мс
            self._chat_watch.timeout.connect(self._watch_chat_proc)
        if not self._chat_watch.isActive():
            self._chat_watch.start()


    def _watch_chat_proc(self):
        """Внутрішній вотчер: коли чат закрився — повертаємо лобі в online."""
        proc = getattr(self, "_chat_proc", None)
        if proc is not None and proc.poll() is None:
            return  # чат ще працює

        # чат завершився
        if hasattr(self, "_chat_watch") and self._chat_watch.isActive():
            self._chat_watch.stop()
        self._chat_proc = None

        self.show()
        if not self.autorefresh.isActive():
            self.autorefresh.start(3000)
        self.info.setText("Сесію завершено. Можна обрати нового співрозмовника.")
        # перепідключитись до реле та повернути статус idle
        self.loop.create_task(self.api.start())
        self.loop.create_task(self.api.set_status("idle"))
        self.loop.create_task(self.api.get_list())



def main():
    app = QtWidgets.QApplication(sys.argv)
    w = LobbyWindow()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
