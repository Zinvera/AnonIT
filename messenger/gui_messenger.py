#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AnonIT Messenger GUI - Clean Modern Design
"""

import logging
from typing import Optional
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QTextEdit, QPushButton, QListWidget, QListWidgetItem,
    QSplitter, QFrame, QMessageBox, QApplication, QStackedWidget
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QFont

logger = logging.getLogger(__name__)

# Clean dark theme with cyan accent
STYLE = """
QWidget {
    background-color: #111111;
    color: #ffffff;
}
QLabel {
    background-color: transparent;
    color: #ffffff;
}
QLineEdit {
    background-color: #1a1a1a;
    border: 1px solid #333333;
    border-radius: 8px;
    padding: 12px;
    color: #ffffff;
}
QLineEdit:focus {
    border: 1px solid #00d4aa;
}
QTextEdit {
    background-color: #1a1a1a;
    border: 1px solid #333333;
    border-radius: 8px;
    padding: 12px;
    color: #ffffff;
}
QListWidget {
    background-color: #1a1a1a;
    border: 1px solid #333333;
    border-radius: 8px;
    padding: 5px;
    outline: none;
}
QListWidget::item {
    background-color: transparent;
    color: #ffffff;
    padding: 12px;
    border-radius: 6px;
    margin: 2px;
}
QListWidget::item:selected {
    background-color: #00d4aa;
    color: #000000;
}
QListWidget::item:hover:!selected {
    background-color: #252525;
}
QPushButton {
    border: none;
    border-radius: 8px;
    padding: 12px 20px;
    font-weight: bold;
}
QScrollBar:vertical {
    background: #1a1a1a;
    width: 8px;
    border-radius: 4px;
}
QScrollBar::handle:vertical {
    background: #444444;
    border-radius: 4px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}
QFrame {
    background-color: transparent;
}
"""


class SignalBridge(QObject):
    message_received = pyqtSignal(str, object)
    connected = pyqtSignal()
    disconnected = pyqtSignal()
    keys_received = pyqtSignal(str)


class MessengerWidget(QWidget):
    def __init__(self, server_url: str = None, parent=None):
        try:
            from .config import DEFAULT_SERVER
        except ImportError:
            DEFAULT_SERVER = "ws://localhost:8765"
        super().__init__(parent)
        self.server_url = server_url or DEFAULT_SERVER
        self.client = None
        self.current_contact: Optional[str] = None
        
        self.signals = SignalBridge()
        self.signals.message_received.connect(self._on_message_received)
        self.signals.connected.connect(self._on_connected)
        self.signals.disconnected.connect(self._on_disconnected)
        
        self._init_ui()
    
    def _init_ui(self):
        self.setStyleSheet(STYLE)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        self.stack = QStackedWidget()
        self.stack.addWidget(self._create_connect_page())
        self.stack.addWidget(self._create_chat_page())
        layout.addWidget(self.stack)
    
    def _create_connect_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Container - wider to fit content
        container = QFrame()
        container.setFixedWidth(450)
        container.setStyleSheet("background-color: #1a1a1a; border-radius: 16px;")
        c_layout = QVBoxLayout(container)
        c_layout.setSpacing(12)
        c_layout.setContentsMargins(40, 35, 40, 35)
        
        # Icon - use text instead of emoji for better rendering
        icon = QLabel("🔐")
        icon.setFont(QFont("Segoe UI Emoji", 36))
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon.setMinimumHeight(60)
        c_layout.addWidget(icon)
        
        # Title
        title = QLabel("AnonIT Messenger")
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        title.setStyleSheet("color: #00d4aa;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setMinimumHeight(35)
        c_layout.addWidget(title)
        
        # Subtitle
        sub = QLabel("End-to-End Encrypted")
        sub.setFont(QFont("Segoe UI", 11))
        sub.setStyleSheet("color: #888888;")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        c_layout.addWidget(sub)
        
        c_layout.addSpacing(25)
        
        # Server label
        lbl = QLabel("Server")
        lbl.setFont(QFont("Segoe UI", 11))
        lbl.setStyleSheet("color: #888888;")
        c_layout.addWidget(lbl)
        
        # Server input
        self.server_input = QLineEdit()
        self.server_input.setText(self.server_url)
        self.server_input.setPlaceholderText("ws://server:8765")
        self.server_input.setMinimumHeight(45)
        c_layout.addWidget(self.server_input)
        
        c_layout.addSpacing(15)
        
        # Connect button
        self.connect_btn = QPushButton("Connect")
        self.connect_btn.setMinimumHeight(48)
        self.connect_btn.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        self.connect_btn.setStyleSheet("""
            QPushButton {
                background-color: #00d4aa;
                color: #000000;
            }
            QPushButton:hover { background-color: #00f0c0; }
        """)
        self.connect_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.connect_btn.clicked.connect(self._connect_to_server)
        c_layout.addWidget(self.connect_btn)
        
        # Status
        self.connect_status = QLabel("")
        self.connect_status.setFont(QFont("Segoe UI", 10))
        self.connect_status.setStyleSheet("color: #888888;")
        self.connect_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.connect_status.setWordWrap(True)
        c_layout.addWidget(self.connect_status)
        
        layout.addWidget(container)
        return page

    def _create_chat_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)
        
        # === TOP BAR - Single row, compact ===
        top = QFrame()
        top.setFixedHeight(50)
        top.setStyleSheet("background-color: #1a1a1a; border-radius: 10px;")
        top_layout = QHBoxLayout(top)
        top_layout.setContentsMargins(12, 0, 12, 0)
        top_layout.setSpacing(10)
        
        # Your ID label
        id_lbl = QLabel("Your ID:")
        id_lbl.setStyleSheet("color: #888888; font-size: 12px;")
        top_layout.addWidget(id_lbl)
        
        # ID value
        self.my_id_label = QLabel("...")
        self.my_id_label.setStyleSheet("font-family: Consolas; font-size: 12px; color: #00d4aa;")
        self.my_id_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        top_layout.addWidget(self.my_id_label)
        
        # Copy button
        copy_btn = QPushButton("📋 Copy")
        copy_btn.setFixedHeight(32)
        copy_btn.setStyleSheet("QPushButton { background: #252525; color: #fff; padding: 0 12px; font-size: 11px; } QPushButton:hover { background: #333; }")
        copy_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        copy_btn.clicked.connect(self._copy_my_id)
        top_layout.addWidget(copy_btn)
        
        top_layout.addStretch()
        
        # Status
        self.status_label = QLabel("● Connected")
        self.status_label.setStyleSheet("color: #00d4aa; font-size: 12px;")
        top_layout.addWidget(self.status_label)
        
        # PANIC
        panic_btn = QPushButton("🚨 PANIC")
        panic_btn.setFixedHeight(32)
        panic_btn.setStyleSheet("QPushButton { background: #ff3b3b; color: #fff; padding: 0 14px; font-size: 11px; font-weight: bold; } QPushButton:hover { background: #ff5555; }")
        panic_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        panic_btn.clicked.connect(self._panic)
        top_layout.addWidget(panic_btn)
        
        # Disconnect
        disc_btn = QPushButton("Disconnect")
        disc_btn.setFixedHeight(32)
        disc_btn.setStyleSheet("QPushButton { background: #252525; color: #fff; padding: 0 14px; font-size: 11px; } QPushButton:hover { background: #333; }")
        disc_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        disc_btn.clicked.connect(self._disconnect)
        top_layout.addWidget(disc_btn)
        
        layout.addWidget(top)
        
        # === MAIN AREA ===
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStyleSheet("QSplitter::handle { background: transparent; width: 8px; }")
        
        # Left: Contacts
        left = QFrame()
        left.setMinimumWidth(220)
        left.setMaximumWidth(280)
        left.setStyleSheet("background-color: #1a1a1a; border-radius: 12px;")
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(12, 12, 12, 12)
        left_layout.setSpacing(10)
        
        contacts_lbl = QLabel("Contacts")
        contacts_lbl.setStyleSheet("font-size: 14px; font-weight: bold; color: #ffffff;")
        left_layout.addWidget(contacts_lbl)
        
        self.contact_list = QListWidget()
        self.contact_list.itemClicked.connect(self._on_contact_selected)
        left_layout.addWidget(self.contact_list)
        
        # Add contact
        add_lbl = QLabel("Add Contact")
        add_lbl.setStyleSheet("color: #888888; font-size: 11px; margin-top: 5px;")
        left_layout.addWidget(add_lbl)
        
        self.add_input = QLineEdit()
        self.add_input.setPlaceholderText("Paste friend's ID...")
        self.add_input.returnPressed.connect(self._add_contact)
        left_layout.addWidget(self.add_input)
        
        add_btn = QPushButton("+ Add")
        add_btn.setStyleSheet("""
            QPushButton {
                background-color: #00d4aa;
                color: #000000;
            }
            QPushButton:hover { background-color: #00f0c0; }
        """)
        add_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        add_btn.clicked.connect(self._add_contact)
        left_layout.addWidget(add_btn)
        
        splitter.addWidget(left)
        
        # Right: Chat
        right = QFrame()
        right.setStyleSheet("background-color: #1a1a1a; border-radius: 12px;")
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)
        
        # Chat header
        chat_header = QFrame()
        chat_header.setStyleSheet("background-color: #222222; border-radius: 12px 12px 0 0;")
        ch_layout = QHBoxLayout(chat_header)
        ch_layout.setContentsMargins(15, 12, 15, 12)
        
        self.chat_name = QLabel("Select a contact")
        self.chat_name.setStyleSheet("font-size: 14px; font-weight: bold; color: #ffffff;")
        ch_layout.addWidget(self.chat_name)
        ch_layout.addStretch()
        
        self.encrypt_badge = QLabel("🔒 Encrypted")
        self.encrypt_badge.setStyleSheet("color: #00d4aa; font-size: 11px;")
        self.encrypt_badge.hide()
        ch_layout.addWidget(self.encrypt_badge)
        
        right_layout.addWidget(chat_header)
        
        # Messages
        self.messages = QTextEdit()
        self.messages.setReadOnly(True)
        self.messages.setStyleSheet("""
            QTextEdit {
                background-color: #111111;
                border: none;
                border-radius: 0;
                padding: 15px;
            }
        """)
        right_layout.addWidget(self.messages)
        
        # Input
        input_frame = QFrame()
        input_frame.setStyleSheet("background-color: #222222; border-radius: 0 0 12px 12px;")
        inp_layout = QHBoxLayout(input_frame)
        inp_layout.setContentsMargins(12, 12, 12, 12)
        inp_layout.setSpacing(10)
        
        self.msg_input = QLineEdit()
        self.msg_input.setPlaceholderText("Type a message...")
        self.msg_input.returnPressed.connect(self._send_message)
        self.msg_input.setEnabled(False)
        inp_layout.addWidget(self.msg_input)
        
        self.send_btn = QPushButton("Send")
        self.send_btn.setStyleSheet("""
            QPushButton {
                background-color: #00d4aa;
                color: #000000;
                padding: 12px 24px;
            }
            QPushButton:hover { background-color: #00f0c0; }
            QPushButton:disabled { background-color: #333333; color: #666666; }
        """)
        self.send_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.send_btn.clicked.connect(self._send_message)
        self.send_btn.setEnabled(False)
        inp_layout.addWidget(self.send_btn)
        
        right_layout.addWidget(input_frame)
        
        splitter.addWidget(right)
        splitter.setSizes([240, 560])
        
        layout.addWidget(splitter)
        return page

    # === CONNECTION ===
    def _connect_to_server(self):
        self.server_url = self.server_input.text().strip()
        if not self.server_url:
            self.connect_status.setText("Enter server address")
            self.connect_status.setStyleSheet("color: #ff5555; font-size: 11px;")
            return
        
        self.connect_btn.setEnabled(False)
        self.connect_btn.setText("Connecting...")
        self.connect_status.setText("Establishing secure connection...")
        self.connect_status.setStyleSheet("color: #888888; font-size: 11px;")
        
        try:
            from .client import MessengerClient
            self.client = MessengerClient(self.server_url)
            self._setup_callbacks()
            self.client.start()
            QTimer.singleShot(3000, self._check_connection)
        except Exception as e:
            self.connect_status.setText(f"Error: {e}")
            self.connect_status.setStyleSheet("color: #ff5555; font-size: 11px;")
            self.connect_btn.setEnabled(True)
            self.connect_btn.setText("🔗 Connect")
    
    def _check_connection(self):
        if self.client and self.client.connected:
            self.my_id_label.setText(self.client.user_id)
            self.stack.setCurrentIndex(1)
        else:
            self.connect_status.setText("Connection failed")
            self.connect_status.setStyleSheet("color: #ff5555; font-size: 11px;")
            self.connect_btn.setEnabled(True)
            self.connect_btn.setText("🔗 Connect")
    
    def _setup_callbacks(self):
        if self.client:
            self.client.on_message = lambda p, m: self.signals.message_received.emit(p, m)
            self.client.on_connected = lambda: self.signals.connected.emit()
            self.client.on_disconnected = lambda: self.signals.disconnected.emit()
    
    def _disconnect(self):
        if self.client:
            self.client.stop()
            self.client = None
        self.stack.setCurrentIndex(0)
        self.connect_btn.setEnabled(True)
        self.connect_btn.setText("🔗 Connect")
        self.connect_status.setText("")
        self.contact_list.clear()
        self.messages.clear()
        self.current_contact = None
    
    def _copy_my_id(self):
        if self.client:
            QApplication.clipboard().setText(self.client.user_id)
            self.my_id_label.setStyleSheet("font-family: Consolas; font-size: 12px; color: #000; background: #00d4aa; padding: 2px 6px; border-radius: 4px;")
            QTimer.singleShot(300, lambda: self.my_id_label.setStyleSheet("font-family: Consolas; font-size: 12px; color: #00d4aa; background: transparent;"))
    
    # === CONTACTS ===
    def _add_contact(self):
        cid = self.add_input.text().strip()
        if not cid or len(cid) < 16:
            return
        if self.client and cid != self.client.user_id:
            self.client.add_contact(cid)
            self._update_contacts()
            self.add_input.clear()
            self._select_contact(cid)
    
    def _on_contact_selected(self, item):
        uid = item.data(Qt.ItemDataRole.UserRole)
        if uid:
            self._select_contact(uid)
    
    def _select_contact(self, uid: str):
        self.current_contact = uid
        contact = self.client.contacts.get(uid) if self.client else None
        name = contact.display_name if contact else uid[:8]
        self.chat_name.setText(f"💬 {name}")
        self.msg_input.setEnabled(True)
        self.send_btn.setEnabled(True)
        self.encrypt_badge.show()
        self._load_messages()
    
    def _update_contacts(self):
        if not self.client:
            return
        self.contact_list.clear()
        for uid, c in self.client.contacts.items():
            item = QListWidgetItem(f"👤 {c.display_name}")
            item.setData(Qt.ItemDataRole.UserRole, uid)
            self.contact_list.addItem(item)
            if uid == self.current_contact:
                item.setSelected(True)
    
    # === MESSAGES ===
    def _load_messages(self):
        self.messages.clear()
        if not self.client or not self.current_contact:
            return
        for msg in self.client.get_messages(self.current_contact):
            self._show_message(msg)
    
    def _show_message(self, msg):
        t = datetime.fromtimestamp(msg.timestamp).strftime("%H:%M")
        if msg.is_outgoing:
            html = f'''<div style="text-align:right;margin:8px 0;">
                <span style="background:#00d4aa;color:#000;padding:10px 14px;border-radius:12px 12px 2px 12px;display:inline-block;max-width:70%;">{msg.content}</span>
                <br><span style="color:#666;font-size:10px;">{t} ✓</span></div>'''
        else:
            html = f'''<div style="text-align:left;margin:8px 0;">
                <span style="background:#252525;color:#fff;padding:10px 14px;border-radius:12px 12px 12px 2px;display:inline-block;max-width:70%;">{msg.content}</span>
                <br><span style="color:#666;font-size:10px;">{t}</span></div>'''
        self.messages.append(html)
        self.messages.verticalScrollBar().setValue(self.messages.verticalScrollBar().maximum())
    
    def _send_message(self):
        if not self.client or not self.current_contact:
            return
        text = self.msg_input.text().strip()
        if not text:
            return
        if self.client.send_message(self.current_contact, text):
            self.msg_input.clear()
            self._load_messages()
        else:
            QTimer.singleShot(2000, lambda: self._retry_send(text))
    
    def _retry_send(self, text):
        if self.client and self.current_contact:
            if self.client.send_message(self.current_contact, text):
                self.msg_input.clear()
                self._load_messages()
    
    # === SIGNALS ===
    def _on_message_received(self, peer_id, msg):
        self._update_contacts()
        if peer_id == self.current_contact:
            self._show_message(msg)
    
    def _on_connected(self):
        self.status_label.setText("● Connected")
        self.status_label.setStyleSheet("color: #00d4aa; font-size: 12px;")
        if self.client:
            self.my_id_label.setText(self.client.user_id)
    
    def _on_disconnected(self):
        self.status_label.setText("● Disconnected")
        self.status_label.setStyleSheet("color: #ff5555; font-size: 12px;")
    
    def _on_keys_received(self, uid):
        self._update_contacts()
    
    def set_server(self, url):
        self.server_url = url
        self.server_input.setText(url)

    # === PANIC ===
    def _panic(self):
        reply = QMessageBox.warning(self, "⚠️ PANIC",
            "This will DELETE:\n• All server messages\n• Local history\n• Your identity\n• All contacts\n\nCannot be undone!",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        reply2 = QMessageBox.critical(self, "🚨 CONFIRM",
            "FINAL WARNING!\nAll data will be destroyed.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        
        if reply2 != QMessageBox.StandardButton.Yes:
            return
        
        if self.client:
            self.client.panic()
        
        self.messages.clear()
        self.contact_list.clear()
        self.current_contact = None
        self.encrypt_badge.hide()
        self._disconnect()
        
        QMessageBox.information(self, "Done", "All data wiped.\nReconnect with new identity.")
