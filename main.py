#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AnonIT - Secure Text Encryption Tool
"""

import atexit
import logging
import sys
import threading
import time
from typing import Optional

import pyperclip
import pystray
import keyboard
from PIL import Image

from crypto import (
    encrypt, decrypt, is_encrypted, 
    has_key, clear_encryption_key, set_encryption_key
)
from gui import AnonITGUI
from icon import create_tray_icon

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)

CLIPBOARD_DELAY = 0.15

class AnonIT:
    def __init__(self) -> None:
        self.gui: Optional[AnonITGUI] = None
        self.tray_icon: Optional[pystray.Icon] = None
        self.running = True
        self._lock = threading.Lock()
        
        atexit.register(self._cleanup)
        logger.info("AnonIT initialized")
    
    def _on_key_change(self, password: str) -> None:
        try:
            set_encryption_key(password)
            logger.info("Key updated")
        except ValueError as e:
            logger.error(f"Failed to set key: {e}")
    
    def _handle_encrypt(self, text: str) -> Optional[str]:
        if not has_key():
            return None
        if not text or not text.strip():
            return None
        try:
            return encrypt(text)
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            return None
    
    def _handle_decrypt(self, text: str) -> Optional[str]:
        if not has_key():
            return None
        if not text or not text.strip():
            return None
        try:
            return decrypt(text)
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return None
    
    def _show_gui(self) -> None:
        if self.gui:
            self.gui.show()
    
    def _handle_f8_hotkey(self) -> None:
        if not has_key():
            self._show_gui()
            return
        
        with self._lock:
            try:
                time.sleep(0.05)
                old_clipboard = pyperclip.paste()
                
                pyperclip.copy('')
                keyboard.send('ctrl+c')
                time.sleep(CLIPBOARD_DELAY)
                
                text = pyperclip.paste()
                if not text or not text.strip():
                    pyperclip.copy(old_clipboard)
                    return
                
                if is_encrypted(text):
                    try:
                        decrypted = decrypt(text)
                        self._show_decrypt_popup(decrypted)
                    except Exception as e:
                        logger.error(f"Decryption failed: {e}")
                else:
                    try:
                        encrypted = encrypt(text)
                        pyperclip.copy(encrypted)
                        keyboard.send('ctrl+v')
                    except Exception as e:
                        logger.error(f"Encryption failed: {e}")
                        pyperclip.copy(old_clipboard)
            except Exception as e:
                logger.error(f"F8 error: {e}")
    
    def _show_decrypt_popup(self, text: str) -> None:
        from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QPushButton
        from PyQt6.QtCore import Qt, QTimer, QSize
        from PyQt6.QtGui import QGuiApplication
        from icons import Icons
        
        def show_popup():
            app = QApplication.instance() or QApplication([])
            
            style = """
            QWidget { background-color: #0a0a0a; color: #ffffff; font-family: 'Segoe UI', sans-serif; }
            QLabel#header { color: #00d4aa; font-size: 20px; font-weight: bold; }
            QTextEdit { background-color: #141414; border: 1px solid #2a2a2a; border-radius: 6px; padding: 12px; color: #ffffff; font-family: 'Consolas', monospace; font-size: 12px; selection-background-color: #00d4aa; }
            QPushButton { border: none; border-radius: 6px; padding: 12px 28px; font-size: 12px; font-weight: bold; }
            QPushButton#primary { background-color: #00d4aa; color: #0a0a0a; }
            QPushButton#primary:hover { background-color: #00f5c4; }
            QPushButton#secondary { background-color: #1e1e1e; color: #888888; }
            QPushButton#secondary:hover { background-color: #2a2a2a; color: #ffffff; }
            """
            
            popup = QWidget()
            popup.setWindowTitle("Decrypted")
            popup.setStyleSheet(style)
            popup.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.Window)
            popup.resize(520, 400)
            
            layout = QVBoxLayout(popup)
            layout.setContentsMargins(24, 24, 24, 24)
            layout.setSpacing(16)
            
            hdr_layout = QHBoxLayout()
            hdr_icon = QLabel()
            hdr_icon.setPixmap(Icons.unlock(24, "#00d4aa").pixmap(QSize(24, 24)))
            hdr_layout.addWidget(hdr_icon)
            header = QLabel("Decrypted Message")
            header.setObjectName("header")
            hdr_layout.addWidget(header)
            hdr_layout.addStretch()
            layout.addLayout(hdr_layout)
            
            text_area = QTextEdit()
            text_area.setPlainText(text)
            layout.addWidget(text_area)
            
            btn_layout = QHBoxLayout()
            copy_btn = QPushButton(" Copy")
            copy_btn.setObjectName("primary")
            copy_btn.setIcon(Icons.copy(18, "#0a0a0a"))
            copy_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            
            def copy_text():
                app.clipboard().setText(text)
                copy_btn.setText(" Copied!")
                QTimer.singleShot(1500, lambda: copy_btn.setText(" Copy"))
            
            copy_btn.clicked.connect(copy_text)
            btn_layout.addWidget(copy_btn)
            btn_layout.addStretch()
            
            close_btn = QPushButton(" Close")
            close_btn.setObjectName("secondary")
            close_btn.clicked.connect(popup.close)
            btn_layout.addWidget(close_btn)
            layout.addLayout(btn_layout)
            
            QTimer.singleShot(60000, popup.close)
            
            screen = QGuiApplication.primaryScreen().geometry()
            popup.move((screen.width() - popup.width()) // 2, (screen.height() - popup.height()) // 2)
            
            popup.show()
            popup.raise_()
            popup.activateWindow()
            
            if QApplication.instance() and not hasattr(app, '_main_running'):
                app.exec()
        
        threading.Thread(target=show_popup, daemon=True).start()
    
    def _cleanup(self) -> None:
        try:
            keyboard.unhook_all()
            clear_encryption_key()
        except: pass
    
    def _quit_app(self) -> None:
        import os
        self._cleanup()
        os._exit(0)
    
    def _create_tray_menu(self) -> pystray.Menu:
        return pystray.Menu(
            pystray.MenuItem("Open AnonIT", lambda: self._show_gui(), default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", lambda: self._quit_app())
        )
    
    def run(self) -> None:
        keyboard.add_hotkey('f8', self._handle_f8_hotkey, suppress=False)
        
        self.gui = AnonITGUI(
            on_key_change=self._on_key_change,
            on_encrypt=self._handle_encrypt,
            on_decrypt=self._handle_decrypt
        )
        
        def run_tray():
            try:
                icon_image = create_tray_icon(64)
                self.tray_icon = pystray.Icon("AnonIT", icon_image, "AnonIT", self._create_tray_menu())
                self.tray_icon.run()
            except Exception as e:
                logger.error(f"Tray error: {e}")
        
        threading.Thread(target=run_tray, daemon=True).start()
        
        print("-" * 30)
        print("AnonIT running...")
        print("F8: Encrypt/Decrypt")
        print("-" * 30)
        
        self.gui.mainloop()

def main() -> int:
    try:
        AnonIT().run()
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception as e:
        logger.exception(f"Fatal: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
