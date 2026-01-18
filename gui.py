#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AnonIT - PyQt6 Dark Theme GUI
==============================

Modern, smooth dark-themed interface for secure text encryption.
Built with PyQt6 for better rendering and animations.

Author: AnonIT Project
License: MIT
"""

import logging
from typing import Callable, Optional

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QTextEdit, QPushButton, QFrame, QSizePolicy
)
from PyQt6.QtCore import Qt, QSize, QTimer
from PyQt6.QtGui import QFont, QIcon, QPixmap

from icons import Icons

logger = logging.getLogger(__name__)

# Stylesheet
DARK_STYLE = """
QMainWindow, QWidget {
    background-color: #0a0a0a;
    color: #ffffff;
    font-family: 'Segoe UI', sans-serif;
}

QLabel {
    color: #ffffff;
    font-size: 13px;
}

QLabel#header {
    color: #00d4aa;
    font-size: 28px;
    font-weight: bold;
}

QLabel#subtitle {
    color: #888888;
    font-size: 11px;
}

QLabel#keyStatus {
    font-size: 11px;
}

QLineEdit {
    background-color: #141414;
    border: 1px solid #2a2a2a;
    border-radius: 6px;
    padding: 10px 12px;
    color: #ffffff;
    font-size: 13px;
    selection-background-color: #00d4aa;
}

QLineEdit:focus {
    border-color: #00d4aa;
}

QTextEdit {
    background-color: #141414;
    border: 1px solid #2a2a2a;
    border-radius: 6px;
    padding: 10px;
    color: #ffffff;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
    selection-background-color: #00d4aa;
}

QTextEdit:focus {
    border-color: #00d4aa;
}

QPushButton {
    border: none;
    border-radius: 6px;
    padding: 10px 15px;
    font-size: 12px;
    font-weight: bold;
}

QPushButton#primary {
    background-color: #00d4aa;
    color: #0a0a0a;
}

QPushButton#primary:hover {
    background-color: #00f5c4;
}

QPushButton#primary:pressed {
    background-color: #00b894;
}

QPushButton#secondary {
    background-color: #1e1e1e;
    color: #ffffff;
}

QPushButton#secondary:hover {
    background-color: #2a2a2a;
}

QPushButton#tertiary {
    background-color: #1e1e1e;
    color: #888888;
}

QPushButton#tertiary:hover {
    background-color: #2a2a2a;
    color: #ffffff;
}

QFrame#statusBar {
    background-color: #141414;
    border-top: 1px solid #2a2a2a;
}
"""


class AnonITGUI(QMainWindow):
    """Main GUI window for AnonIT encryption tool."""
    
    def __init__(self,
                 on_key_change: Optional[Callable[[str], None]] = None,
                 on_encrypt: Optional[Callable[[str], Optional[str]]] = None,
                 on_decrypt: Optional[Callable[[str], Optional[str]]] = None):
        
        self.app: Optional[QApplication] = None
        self._app_created = False
        self.on_key_change = on_key_change
        self.on_encrypt = on_encrypt
        self.on_decrypt = on_decrypt
        self._initialized = False
        
    def _ensure_app(self):
        """Ensure QApplication exists."""
        if QApplication.instance() is None:
            self.app = QApplication([])
            self._app_created = True
        else:
            self.app = QApplication.instance()
    
    def _init_ui(self):
        """Initialize the UI components."""
        if self._initialized:
            return
            
        self._ensure_app()
        super().__init__()
        
        self.setWindowTitle("AnonIT")
        self.setMinimumSize(600, 500)
        self.resize(600, 500)
        self.setStyleSheet(DARK_STYLE)
        
        # Set window icon
        try:
            from icon import create_icon
            icon_img = create_icon(64)
            # Convert PIL to QPixmap
            from io import BytesIO
            buffer = BytesIO()
            icon_img.save(buffer, format='PNG')
            pixmap = QPixmap()
            pixmap.loadFromData(buffer.getvalue())
            self.setWindowIcon(QIcon(pixmap))
        except Exception as e:
            logger.warning(f"Could not set icon: {e}")
        
        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(24, 24, 24, 0)
        layout.setSpacing(16)
        
        # Header
        self._create_header(layout)
        
        # Key section
        self._create_key_section(layout)
        
        # Text section
        self._create_text_section(layout)
        
        # Buttons
        self._create_buttons(layout)
        
        # Status bar
        self._create_status_bar(layout)
        
        self._initialized = True
        logger.info("PyQt6 GUI initialized")
    
    def _create_header(self, layout: QVBoxLayout):
        """Create header section."""
        header = QLabel("AnonIT")
        header.setObjectName("header")
        layout.addWidget(header)
        
        subtitle = QLabel("Secure AES-256 Encryption • Keys stored in memory only")
        subtitle.setObjectName("subtitle")
        layout.addWidget(subtitle)
    
    def _create_key_section(self, layout: QVBoxLayout):
        """Create key input section."""
        key_label = QLabel("Encryption Key")
        layout.addWidget(key_label)
        
        key_row = QHBoxLayout()
        key_row.setSpacing(8)
        
        self.key_input = QLineEdit()
        self.key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.key_input.setPlaceholderText("Enter your encryption key...")
        self.key_input.returnPressed.connect(self._set_key)
        key_row.addWidget(self.key_input)
        
        self.show_key_btn = QPushButton()
        self.show_key_btn.setObjectName("secondary")
        self.show_key_btn.setFixedSize(45, 40)
        self.show_key_btn.setIcon(Icons.eye(20, "#888888"))
        self.show_key_btn.setIconSize(QSize(20, 20))
        self.show_key_btn.setToolTip("View/Hide Key")
        self.show_key_btn.clicked.connect(self._toggle_key_visibility)
        self.show_key_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        key_row.addWidget(self.show_key_btn)
        
        set_key_btn = QPushButton("Set Key")
        set_key_btn.setObjectName("primary")
        set_key_btn.clicked.connect(self._set_key)
        set_key_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        key_row.addWidget(set_key_btn)
        
        layout.addLayout(key_row)
    
    def _create_text_section(self, layout: QVBoxLayout):
        """Create text area section."""
        text_label = QLabel("Text")
        layout.addWidget(text_label)
        
        self.text_area = QTextEdit()
        self.text_area.setPlaceholderText("Enter text to encrypt or paste encrypted text to decrypt...")
        self.text_area.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout.addWidget(self.text_area)
    
    def _create_buttons(self, layout: QVBoxLayout):
        """Create action buttons."""
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        
        encrypt_btn = QPushButton(" Encrypt")
        encrypt_btn.setObjectName("primary")
        encrypt_btn.setIcon(Icons.lock(18, "#0a0a0a"))
        encrypt_btn.setIconSize(QSize(18, 18))
        encrypt_btn.clicked.connect(self._encrypt_text)
        encrypt_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_row.addWidget(encrypt_btn)
        
        decrypt_btn = QPushButton(" Decrypt")
        decrypt_btn.setObjectName("secondary")
        decrypt_btn.setIcon(Icons.unlock(18, "#ffffff"))
        decrypt_btn.setIconSize(QSize(18, 18))
        decrypt_btn.clicked.connect(self._decrypt_text)
        decrypt_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_row.addWidget(decrypt_btn)
        
        self.copy_btn = QPushButton(" Copy")
        self.copy_btn.setObjectName("secondary")
        self.copy_btn.setIcon(Icons.copy(18, "#ffffff"))
        self.copy_btn.setIconSize(QSize(18, 18))
        self.copy_btn.clicked.connect(self._copy_text)
        self.copy_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_row.addWidget(self.copy_btn)
        
        btn_row.addStretch()
        
        clear_btn = QPushButton(" Clear")
        clear_btn.setObjectName("tertiary")
        clear_btn.setIcon(Icons.trash(16, "#888888"))
        clear_btn.setIconSize(QSize(16, 16))
        clear_btn.clicked.connect(self._clear_text)
        clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_row.addWidget(clear_btn)
        
        layout.addLayout(btn_row)
    
    def _create_status_bar(self, layout: QVBoxLayout):
        """Create status bar."""
        status_frame = QFrame()
        status_frame.setObjectName("statusBar")
        status_frame.setFixedHeight(45)
        status_frame.setStyleSheet("""
            QFrame#statusBar {
                background-color: #141414;
                border: 1px solid #2a2a2a;
                border-radius: 10px;
                margin: 8px 0px;
            }
        """)
        
        status_layout = QHBoxLayout(status_frame)
        status_layout.setContentsMargins(20, 0, 20, 0)
        
        self.status_label = QLabel("Ready • Press F8 to Encrypt/Decrypt selected text")
        self.status_label.setStyleSheet("color: #666666; font-size: 11px; background: transparent;")
        status_layout.addWidget(self.status_label)
        
        status_layout.addStretch()
        
        self.key_status = QLabel("● No key set")
        self.key_status.setObjectName("keyStatus")
        self.key_status.setStyleSheet("color: #ff4757; font-size: 11px; background: transparent;")
        status_layout.addWidget(self.key_status)
        
        layout.addWidget(status_frame)
    
    def _toggle_key_visibility(self):
        """Toggle password visibility."""
        if self.key_input.echoMode() == QLineEdit.EchoMode.Password:
            self.key_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.show_key_btn.setIcon(Icons.eye_off(20, "#00d4aa"))
        else:
            self.key_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_key_btn.setIcon(Icons.eye(20, "#888888"))
    
    def _set_key(self):
        """Set the encryption key."""
        key = self.key_input.text()
        if not key:
            self.status_label.setText("⚠ Please enter an encryption key")
            return
        if len(key) < 4:
            self.status_label.setText("⚠ Key must be at least 4 characters")
            return
        
        if self.on_key_change:
            self.on_key_change(key)
        
        self.key_status.setText("● Key active")
        self.key_status.setStyleSheet("color: #00d4aa; font-size: 11px; background: transparent;")
        self.status_label.setText("Encryption key set successfully")
        
        self.key_input.clear()
        self.key_input.setEchoMode(QLineEdit.EchoMode.Password)
        
        logger.info("Key set via GUI")
    
    def _encrypt_text(self):
        """Encrypt text in text area."""
        text = self.text_area.toPlainText()
        if not text.strip():
            self.status_label.setText("⚠ No text to encrypt")
            return
        
        if self.on_encrypt:
            result = self.on_encrypt(text)
            if result:
                self.text_area.setPlainText(result)
                self.status_label.setText("Text encrypted successfully")
            else:
                self.status_label.setText("⚠ Encryption failed - is key set?")
    
    def _decrypt_text(self):
        """Decrypt text in text area."""
        text = self.text_area.toPlainText()
        if not text.strip():
            self.status_label.setText("⚠ No text to decrypt")
            return
        
        if self.on_decrypt:
            result = self.on_decrypt(text)
            if result:
                self.text_area.setPlainText(result)
                self.status_label.setText("Text decrypted successfully")
            else:
                self.status_label.setText("⚠ Decryption failed - wrong key?")
    
    def _copy_text(self):
        """Copy text to clipboard."""
        text = self.text_area.toPlainText()
        if not text:
            self.status_label.setText("⚠ Nothing to copy")
            return
            
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        
        self.status_label.setText("Content copied to clipboard")
        
        # Visual feedback
        self.copy_btn.setText(" Copied!")
        self.copy_btn.setIcon(Icons.check(18, "#00d4aa"))
        self.copy_btn.setStyleSheet("color: #00d4aa;")
        
        def restore():
            self.copy_btn.setText(" Copy")
            self.copy_btn.setIcon(Icons.copy(18, "#ffffff"))
            self.copy_btn.setStyleSheet("")
        
        QTimer.singleShot(1500, restore)
    
    def _clear_text(self):
        """Clear text area."""
        self.text_area.clear()
        self.status_label.setText("Ready")
    
    def show(self):
        """Show the window."""
        self._init_ui()
        super().show()
        self.raise_()
        self.activateWindow()
    
    def mainloop(self):
        """Start the application event loop."""
        self._init_ui()
        super().show()
        if self._app_created and self.app:
            self.app.exec()
    
    def quit(self):
        """Quit the application."""
        if self.app:
            self.app.quit()
    
    def closeEvent(self, event):
        """Hide instead of close."""
        event.ignore()
        self.hide()


# Standalone testing
if __name__ == "__main__":
    def test_encrypt(text):
        return f"ANON[encrypted:{len(text)}]IT"
    
    def test_decrypt(text):
        return "Decrypted content"
    
    gui = AnonITGUI(
        on_key_change=lambda k: print(f"Key: {k[:3]}..."),
        on_encrypt=test_encrypt,
        on_decrypt=test_decrypt
    )
    gui.mainloop()
