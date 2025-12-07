"""PyQt window classes for the secure chat GUI."""
from __future__ import annotations

from datetime import datetime
from typing import Dict, Optional

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QTextOption
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .app import ChatController, is_password_strong
from .styles import ACCENT, BORDER_RADIUS, PADDING, PRIMARY_BG, SIDEBAR_BG, TEXT_MUTED, TEXT_PRIMARY


class ServerConfigDialog(QDialog):
    """Dialog used to collect the server URL on first launch."""

    def __init__(self, parent: QWidget | None = None, prefill: str | None = None):
        super().__init__(parent)
        self.setWindowTitle("Server configuration")
        layout = QFormLayout(self)
        self.url_input = QLineEdit(prefill or "http://127.0.0.1:8000")
        layout.addRow("Server URL", self.url_input)
        btn = QPushButton("Save & connect")
        btn.clicked.connect(self.accept)
        layout.addWidget(btn)

    def server_url(self) -> str:
        return self.url_input.text().strip()


class LoginWindow(QMainWindow):
    """Login and registration entry window."""

    logged_in = pyqtSignal()

    def __init__(self, controller: ChatController):
        super().__init__()
        self.controller = controller
        self.setWindowTitle("Secure Chat – Sign in")
        self.resize(640, 420)
        self._ensure_server_url()
        self._build_ui()

    def _ensure_server_url(self) -> None:
        if not self.controller.base_url:
            dialog = ServerConfigDialog(self)
            if dialog.exec() == QDialog.DialogCode.Accepted:
                self.controller.set_base_url(dialog.server_url())
            else:
                self.close()
        else:
            self.controller.set_base_url(self.controller.base_url)

    def _build_ui(self) -> None:
        tabs = QTabWidget()
        tabs.addTab(self._build_login_tab(), "Login")
        tabs.addTab(self._build_register_tab(), "Register")
        self.setCentralWidget(tabs)

    def _build_login_tab(self) -> QWidget:
        widget = QWidget()
        layout = QFormLayout(widget)
        self.login_input = QLineEdit()
        self.login_password = QLineEdit()
        self.login_password.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addRow("Login", self.login_input)
        layout.addRow("Password", self.login_password)
        self.login_error = QLabel()
        self.login_error.setStyleSheet("color: red")
        login_btn = QPushButton("Log in")
        login_btn.clicked.connect(self._login)
        layout.addRow(self.login_error)
        layout.addRow(login_btn)
        return widget

    def _build_register_tab(self) -> QWidget:
        widget = QWidget()
        layout = QFormLayout(widget)
        self.reg_login = QLineEdit()
        self.reg_password = QLineEdit()
        self.reg_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.reg_confirm = QLineEdit()
        self.reg_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.reg_nick = QLineEdit()
        layout.addRow("Login", self.reg_login)
        layout.addRow("Password", self.reg_password)
        layout.addRow("Confirm", self.reg_confirm)
        layout.addRow("Nickname", self.reg_nick)
        hint = QLabel("Password: min 10 chars, not trivial")
        hint.setStyleSheet(f"color: {TEXT_MUTED}")
        layout.addRow(hint)
        self.reg_error = QLabel()
        self.reg_error.setStyleSheet("color: red")
        reg_btn = QPushButton("Register")
        reg_btn.clicked.connect(self._register)
        layout.addRow(self.reg_error)
        layout.addRow(reg_btn)
        return widget

    def _login(self) -> None:
        self.login_error.clear()
        try:
            self.controller.login(self.login_input.text().strip(), self.login_password.text())
        except Exception as exc:  # noqa: BLE001
            self.login_error.setText(str(exc))
            return
        self.logged_in.emit()

    def _register(self) -> None:
        self.reg_error.clear()
        password = self.reg_password.text()
        if password != self.reg_confirm.text():
            self.reg_error.setText("Passwords do not match")
            return
        if not is_password_strong(password):
            self.reg_error.setText("Password does not meet policy")
            return
        try:
            self.controller.register(
                self.reg_login.text().strip(),
                password,
                self.reg_nick.text().strip(),
            )
        except Exception as exc:  # noqa: BLE001
            self.reg_error.setText(str(exc))
            return
        QMessageBox.information(self, "Registered", "Account created. You can log in now.")


class ProfileDialog(QDialog):
    """Profile and password change dialog."""

    logout_requested = pyqtSignal()

    def __init__(self, controller: ChatController, parent: QWidget | None = None):
        super().__init__(parent)
        self.controller = controller
        self.setWindowTitle("Profile & Settings")
        self.resize(420, 300)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        user = self.controller.user or {}
        info = QLabel(f"Logged in as <b>{user.get('nickname', '')}</b> ({user.get('login', '')})")
        fingerprint = QLabel(f"Key fingerprint: {self.controller.fingerprint()}")
        fingerprint.setStyleSheet(f"color: {TEXT_MUTED}")
        layout.addWidget(info)
        layout.addWidget(fingerprint)

        form = QFormLayout()
        self.old_pw = QLineEdit()
        self.old_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_pw = QLineEdit()
        self.new_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_pw_confirm = QLineEdit()
        self.new_pw_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Current password", self.old_pw)
        form.addRow("New password", self.new_pw)
        form.addRow("Confirm new", self.new_pw_confirm)
        layout.addLayout(form)

        hint = QLabel("Password: min 10 chars, avoid common ones")
        hint.setStyleSheet(f"color: {TEXT_MUTED}")
        layout.addWidget(hint)

        btn_row = QHBoxLayout()
        change_btn = QPushButton("Change password")
        logout_btn = QPushButton("Logout")
        btn_row.addWidget(change_btn)
        btn_row.addWidget(logout_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        change_btn.clicked.connect(self._change_password)
        logout_btn.clicked.connect(self._logout)

    def _change_password(self) -> None:
        old = self.old_pw.text()
        new = self.new_pw.text()
        confirm = self.new_pw_confirm.text()
        if new != confirm:
            QMessageBox.warning(self, "Error", "New passwords do not match")
            return
        if not is_password_strong(new):
            QMessageBox.warning(self, "Error", "New password does not meet policy")
            return
        try:
            self.controller.change_password(old, new)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "Error", str(exc))
            return
        QMessageBox.information(self, "Success", "Password changed")
        self.old_pw.clear()
        self.new_pw.clear()
        self.new_pw_confirm.clear()

    def _logout(self) -> None:
        self.controller.logout()
        self.logout_requested.emit()
        self.accept()


class MainChatWindow(QMainWindow):
    """Main chat UI with sidebar and message area."""

    logged_out = pyqtSignal()

    def __init__(self, controller: ChatController):
        super().__init__()
        self.controller = controller
        self.current_peer_id: Optional[int] = None
        self.user_cache: Dict[int, Dict] = {}
        self.setWindowTitle("Secure Chat")
        self.resize(1024, 720)
        self._build_ui()
        self.refresh_users()
        self.poller = QTimer(self)
        self.poller.timeout.connect(self._poll_messages)
        self.poller.start(2500)

    def _build_ui(self) -> None:
        container = QWidget()
        layout = QHBoxLayout(container)

        sidebar = self._build_sidebar()
        layout.addWidget(sidebar, 1)

        main_area = self._build_main_area()
        layout.addWidget(main_area, 3)

        container.setStyleSheet(
            f"QWidget {{ background: {PRIMARY_BG}; color: {TEXT_PRIMARY}; }}\n"
            f"QLineEdit, QTextEdit {{ background: white; border: 1px solid #d1d5db; border-radius: {BORDER_RADIUS}px; }}\n"
            f"QPushButton {{ background: {ACCENT}; color: white; padding: 6px 12px; border-radius: {BORDER_RADIUS}px; }}\n"
            f"QPushButton:hover {{ background: #2563eb; }}"
        )
        self.setCentralWidget(container)

    def _build_sidebar(self) -> QWidget:
        widget = QWidget()
        widget.setStyleSheet(f"background: {SIDEBAR_BG}; color: white")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(PADDING, PADDING, PADDING, PADDING)

        user = self.controller.user or {}
        profile_box = QGroupBox("Profile")
        profile_layout = QVBoxLayout(profile_box)
        profile_layout.addWidget(QLabel(f"{user.get('nickname', '')}"))
        profile_layout.addWidget(QLabel(f"{user.get('login', '')}"))
        profile_btn = QPushButton("Open profile")
        profile_btn.clicked.connect(self._open_profile)
        profile_layout.addWidget(profile_btn)
        layout.addWidget(profile_box)

        search_box = QGroupBox("Find user")
        search_layout = QHBoxLayout(search_box)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("@nickname")
        search_btn = QPushButton("Search")
        search_btn.clicked.connect(self._search_user)
        search_layout.addWidget(self.search_input)
        search_layout.addWidget(search_btn)
        layout.addWidget(search_box)

        self.chat_list = QListWidget()
        self.chat_list.itemSelectionChanged.connect(self._chat_selected)
        layout.addWidget(self.chat_list, 1)
        layout.addStretch()
        return widget

    def _build_main_area(self) -> QWidget:
        widget = QWidget()
        grid = QGridLayout(widget)
        self.chat_title = QLabel("Select a chat")
        self.chat_title.setStyleSheet("font-size: 16px; font-weight: bold")
        grid.addWidget(self.chat_title, 0, 0, 1, 2)

        self.messages_view = QTextEdit()
        self.messages_view.setReadOnly(True)
        self.messages_view.setWordWrapMode(QTextOption.WrapMode.WordWrap)
        grid.addWidget(self.messages_view, 1, 0, 1, 2)

        self.message_input = QTextEdit()
        self.message_input.setFixedHeight(80)
        grid.addWidget(self.message_input, 2, 0)

        send_btn = QPushButton("Send")
        send_btn.clicked.connect(self._send_message)
        grid.addWidget(send_btn, 2, 1)
        return widget

    def refresh_users(self) -> None:
        try:
            users = self.controller.list_users()
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "Error", f"Failed to load users: {exc}")
            return
        for u in users:
            self.user_cache[u["id"]] = u
            if u.get("id") != (self.controller.user or {}).get("id"):
                self._ensure_chat_list_item(u)

    def _ensure_chat_list_item(self, user: Dict) -> None:
        existing = [self.chat_list.item(i) for i in range(self.chat_list.count())]
        for item in existing:
            if item.data(Qt.ItemDataRole.UserRole) == user["id"]:
                return
        item = QListWidgetItem(user["nickname"])
        item.setData(Qt.ItemDataRole.UserRole, user["id"])
        self.chat_list.addItem(item)

    def _chat_selected(self) -> None:
        items = self.chat_list.selectedItems()
        if not items:
            return
        peer_id = items[0].data(Qt.ItemDataRole.UserRole)
        self.current_peer_id = peer_id
        peer = self.user_cache.get(peer_id)
        self.controller.last_message_ids[peer_id] = 0
        self.chat_title.setText(f"Chat with {peer.get('nickname') if peer else peer_id}")
        self.messages_view.clear()
        self._poll_messages()

    def _format_message(self, msg: Dict) -> str:
        ts = msg.get("created_at", "")
        if isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts)
                ts = dt.strftime("%H:%M")
            except Exception:  # noqa: BLE001
                pass
        direction = "you" if msg.get("sender_id") == (self.controller.user or {}).get("id") else "them"
        align = "right" if direction == "you" else "left"
        bubble_color = "#dbeafe" if direction == "you" else "#e5e7eb"
        text = msg.get("plaintext", "")
        return (
            f'<div style="text-align:{align}; margin:6px 0;">'
            f'<span style="display:inline-block; background:{bubble_color}; padding:8px; border-radius:8px;">'
            f"<b>[{ts}] {direction}:</b> {text}</span></div>"
        )

    def _append_messages(self, messages: list[Dict]) -> None:
        cursor = self.messages_view.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        for msg in messages:
            cursor.insertHtml(self._format_message(msg))
        self.messages_view.setTextCursor(cursor)
        self.messages_view.ensureCursorVisible()

    def _poll_messages(self) -> None:
        if self.current_peer_id is None:
            return
        try:
            msgs = self.controller.fetch_messages(self.current_peer_id)
        except Exception:
            return
        if msgs:
            self._append_messages(msgs)

    def _send_message(self) -> None:
        if self.current_peer_id is None:
            QMessageBox.warning(self, "No chat", "Select a chat first")
            return
        text = self.message_input.toPlainText().strip()
        if not text:
            return
        try:
            self.controller.send_message(self.current_peer_id, text)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "Error", str(exc))
            return
        self.message_input.clear()
        self._poll_messages()

    def _search_user(self) -> None:
        nickname = self.search_input.text().strip()
        if not nickname:
            return
        try:
            users = self.controller.list_users(nickname=nickname)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "Error", f"Search failed: {exc}")
            return
        if not users:
            QMessageBox.information(self, "Not found", "No user with that nickname")
            return
        peer = users[0]
        self.user_cache[peer["id"]] = peer
        self._ensure_chat_list_item(peer)
        matches = self.chat_list.findItems(peer["nickname"], Qt.MatchFlag.MatchExactly)
        if matches:
            self.chat_list.setCurrentItem(matches[0])

    def _open_profile(self) -> None:
        dialog = ProfileDialog(self.controller, self)
        dialog.logout_requested.connect(self._handle_logout)
        dialog.exec()

    def _handle_logout(self) -> None:
        self.logged_out.emit()
        self.close()


class ChatApplication:
    """Top-level class wiring windows together."""

    def __init__(self):
        self.app = QApplication.instance() or QApplication([])
        self.controller = ChatController()
        self.login_window = LoginWindow(self.controller)
        self.main_window: Optional[MainChatWindow] = None
        self.login_window.logged_in.connect(self._on_logged_in)

    def _on_logged_in(self) -> None:
        self.main_window = MainChatWindow(self.controller)
        self.main_window.logged_out.connect(self._show_login)
        self.login_window.hide()
        self.main_window.show()

    def _show_login(self) -> None:
        self.login_window.show()
        if self.main_window:
            self.main_window.close()
            self.main_window = None

    def run(self) -> int:
        self.login_window.show()
        return self.app.exec()


__all__ = ["ChatApplication", "LoginWindow", "MainChatWindow", "ProfileDialog"]
