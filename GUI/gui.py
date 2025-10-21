# gui.py
import os
import sys
import asyncio
import threading
from typing import Optional, Callable

from PySide6.QtCore import Qt, QEvent, QDateTime, QTimer, Signal, Slot
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QTextEdit, QPushButton, QScrollArea, QSizePolicy
)

# Якщо використовуєш python-dotenv — підтягнемо .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ── ENV конфіг ─────────────────────────────────────────────────────────────
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8765"))
DEBUG = os.getenv("CHAT_DEBUG", "0") == "1"

# Імпортуємо твій мережевий клієнт.
# Залиши саме такий імпорт, якщо у проєкті є пакет net/ з __init__.py.
# Якщо файли лежать поряд з gui.py — зміни на: from net_client import NetClient
try:
    from net.net_client import NetClient
except Exception:
    from net_client import NetClient  # fallback на випадок локального запуску поряд із файлом


# ───────────────────────────────────────────────────────────────────────────
# Допоміжний віджет "бульбашка повідомлення"
# ───────────────────────────────────────────────────────────────────────────
class MessageBubble(QWidget):
    def __init__(self, text: str, outgoing: bool):
        super().__init__()
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)

        root = QVBoxLayout(self)
        root.setContentsMargins(10, 6, 10, 6)
        root.setSpacing(2)

        # Хедер: напрямок + час
        hdr = QLabel()
        t = QDateTime.currentDateTime().toString("yyyy-MM-dd HH:mm:ss")
        hdr.setText(("You →" if outgoing else "← Peer") + f"    {t}")
        hdr.setStyleSheet("color: #888; font-size: 12px;")
        hdr.setAlignment(Qt.AlignRight if outgoing else Qt.AlignLeft)
        root.addWidget(hdr)

        body = QLabel(text)
        body.setWordWrap(True)
        body.setTextInteractionFlags(Qt.TextSelectableByMouse)
        body.setStyleSheet(
            """
            background: rgba(80,80,80,0.15);
            border: 1px solid rgba(120,120,120,0.25);
            border-radius: 10px;
            padding: 8px 10px;
            font-size: 14px;
            """
        )
        body.setAlignment(Qt.AlignRight if outgoing else Qt.AlignLeft)
        root.addWidget(body)


# ───────────────────────────────────────────────────────────────────────────
# Тред з asyncio-циклом і NetClient усередині
# ───────────────────────────────────────────────────────────────────────────
class ClientLoopThread(threading.Thread):
    """
    Окремий тред, що:
      - створює власний asyncio loop,
      - піднімає NetClient і підключається до релея,
      - надає thread-safe метод для відправки повідомлень.
    """
    def __init__(self, host: str, port: int, on_plain_rx: Callable[[str], None]):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.on_plain_rx = on_plain_rx
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.client: Optional[NetClient] = None
        self._stop_event = threading.Event()

    def run(self):
        # власний event loop цього треда
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.client = NetClient(self.host, self.port, on_plain_rx=self.on_plain_rx)
        # головне завдання — конект і читання
        main_coro = self._main()
        try:
            self.loop.run_until_complete(main_coro)
        finally:
            try:
                self.loop.run_until_complete(self._cleanup())
            except Exception:
                pass
            self.loop.close()

    async def _main(self):
        try:
            if DEBUG:
                print(f"[GUI-LOOP] connecting to {self.host}:{self.port}")
            await self.client.connect()
            if DEBUG:
                print("[GUI-LOOP] connected; entering recv loop")
            # Читальний цикл клієнта всередині connect() / run() — залежить від твоєї реалізації.
            # Якщо твій NetClient сам піднімає читання у connect(), цього достатньо.
            # Якщо ні — тут можна було б await self.client.read_forever()
            # Але виходимо по _stop_event.
            while not self._stop_event.is_set():
                await asyncio.sleep(0.05)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            if DEBUG:
                print(f"[GUI-LOOP] exception: {e}")

    async def _cleanup(self):
        if DEBUG:
            print("[GUI-LOOP] cleanup...")
        try:
            if self.client and hasattr(self.client, "close"):
                await self.client.close()  # якщо реалізовано
        except Exception:
            pass

    def stop(self):
        self._stop_event.set()
        if self.loop:
            # Акуратно зупиняємо головне завдання
            for task in asyncio.all_tasks(loop=self.loop):
                task.cancel()

    def send_text(self, text: str):
        """Thread-safe відправка: викликає NetClient.send_plain у його циклі."""
        if not text or not self.loop or not self.client:
            return
        fut = asyncio.run_coroutine_threadsafe(self.client.send_plain(text), self.loop)
        # бажано з’їсти винятки, щоб не вивалюватися у консоль
        try:
            fut.result(timeout=10)
        except Exception as e:
            if DEBUG:
                print(f"[GUI-LOOP] send error: {e}")


# ───────────────────────────────────────────────────────────────────────────
# Головне вікно чату
# ───────────────────────────────────────────────────────────────────────────
class ChatWindow(QMainWindow):
    # Сигнал для доставки вхідного тексту з фонового треда
    message_in = Signal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Chat — Qt GUI")
        self.resize(720, 520)

        # Підписуємо сигнал на додавання повідомлення (QueuedConnection крос-тредом)
        self.message_in.connect(self._on_message_in)

        # ── Верхній статус бар ──────────────────────────────────────────────
        root = QVBoxLayout()
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        self.top = QLabel(f"Relay: {HOST}:{PORT}   |   Debug={'ON' if DEBUG else 'OFF'}")
        self.top.setStyleSheet("font-weight: 600;")
        root.addWidget(self.top)

        # ── Скролювана область з історією ──────────────────────────────────
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        root.addWidget(self.scroll, 1)

        self.viewport = QWidget()
        self.scroll.setWidget(self.viewport)
        self.chat_box = QVBoxLayout(self.viewport)
        self.chat_box.setContentsMargins(8, 8, 8, 8)
        self.chat_box.setSpacing(6)
        # "розтягувач", щоб бульбашки йшли зверху
        self.chat_box.addStretch(1)

        # ── Нижня панель вводу ──────────────────────────────────────────────
        bottom = QHBoxLayout()
        bottom.setSpacing(8)

        self.input = QTextEdit()
        self.input.setPlaceholderText("Напишіть повідомлення…")
        self.input.setFixedHeight(64)
        bottom.addWidget(self.input, 1)

        self.btn_send = QPushButton("Send")
        self.btn_send.setDefault(True)
        self.btn_send.clicked.connect(self._on_send_clicked)
        bottom.addWidget(self.btn_send, 0)

        root.addLayout(bottom)

        # ── Центральний віджет ─────────────────────────────────────────────
        central = QWidget()
        central.setLayout(root)
        self.setCentralWidget(central)

        # ── Мережевий клієнт у фоні ────────────────────────────────────────
        self.net = ClientLoopThread(
            HOST, PORT,
            on_plain_rx=self._deliver_from_bg  # <- отримаємо текст у фоновому треді
        )
        self.net.start()

        # Enter відправляє (Shift+Enter — новий рядок)
        self.input.installEventFilter(self)

    # ── Події ───────────────────────────────────────────────────────────────
    def eventFilter(self, obj, ev: QEvent):
        if obj is self.input and ev.type() == QEvent.KeyPress:
            # Enter без Shift — відправити
            if ev.key() in (Qt.Key_Return, Qt.Key_Enter) and not (ev.modifiers() & Qt.ShiftModifier):
                self._on_send_clicked()
                return True
        return super().eventFilter(obj, ev)

    # ── Колбек із фонового треда NetClient → Qt сигнал ────────────────────
    def _deliver_from_bg(self, text: str) -> None:
        # ВАЖЛИВО: emit із будь-якого треда безпечно доставить у головний тред
        self.message_in.emit(text)

    # ── Обробка сигналу у головному треді ─────────────────────────────────
    @Slot(str)
    def _on_message_in(self, text: str):
        self.add_message(text, outgoing=False)

    # ── Додавання бульбашки і автопрокрутка ───────────────────────────────
    def add_message(self, text: str, outgoing: bool):
        # вставляємо перед розтягувальником (останній елемент)
        idx = self.chat_box.count() - 1
        self.chat_box.insertWidget(idx, MessageBubble(text, outgoing))
        QTimer.singleShot(0, self._scroll_to_bottom)

    def _scroll_to_bottom(self):
        sb = self.scroll.verticalScrollBar()
        sb.setValue(sb.maximum())

    # ── Відправка повідомлення ────────────────────────────────────────────
    def _on_send_clicked(self):
        text = self.input.toPlainText().strip()
        if not text:
            return
        # локально покажемо бульбашку outgoing
        self.add_message(text, outgoing=True)
        self.input.clear()
        # відішлемо через мережевий клієнт (thread-safe)
        self.net.send_text(text)

    # ── Закриття вікна: акуратний shutdown ────────────────────────────────
    def closeEvent(self, ev):
        try:
            self.net.stop()
        except Exception:
            pass
        return super().closeEvent(ev)


# ───────────────────────────────────────────────────────────────────────────
# Підтримка зовнішнього QSS (необов’язково)
# ───────────────────────────────────────────────────────────────────────────
def load_qss(app: QApplication):
    path = os.path.join(os.path.dirname(__file__), "style.qss")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            app.setStyleSheet(f.read())


# ───────────────────────────────────────────────────────────────────────────
# Точка входу
# ───────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = QApplication(sys.argv)
    load_qss(app)
    w = ChatWindow()
    w.show()
    sys.exit(app.exec())
