#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AnonIT - Secure Text Encryption Tool
=====================================

A system-wide encryption utility that allows you to encrypt and decrypt
text anywhere using global hotkeys.

Features:
    - AES-256-GCM authenticated encryption
    - Argon2id password-based key derivation
    - Global hotkeys work in any application
    - System tray integration
    - Modern dark-themed GUI

Usage:
    1. Start the application
    2. Enter your encryption key in the GUI
    3. Select text anywhere and press Ctrl+Shift+E to encrypt
    4. Select encrypted text and press Ctrl+Shift+D to decrypt

Hotkeys:
    Ctrl+Shift+E - Encrypt selected text
    Ctrl+Shift+D - Decrypt selected text

Security Notes:
    - Keys are stored only in memory, never on disk
    - Memory is protected using Windows DPAPI when available
    - Keys are securely wiped on application exit

Author: AnonIT Project
License: MIT
Version: 1.0.0
"""

import atexit
import logging
import sys
import threading
import time
from typing import Optional

import keyboard
import pyperclip
import pystray
from PIL import Image

from crypto import (
    encrypt, decrypt, is_encrypted, 
    has_key, clear_encryption_key, set_encryption_key
)
from gui import AnonITGUI
from icon import create_tray_icon

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)

# Constants
CLIPBOARD_DELAY = 0.2  # Seconds to wait for clipboard operations
HOTKEY_DELAY = 0.05    # Seconds to wait after hotkey press


class AnonIT:
    """
    Main application controller for AnonIT.
    
    Coordinates between:
    - GUI window for key entry and manual encryption
    - System tray icon for background operation
    - Global hotkeys for system-wide encryption
    
    Attributes:
        gui: The main GUI window instance.
        tray_icon: System tray icon for background access.
        running: Flag indicating if application is running.
    
    Thread Safety:
        The application runs multiple threads:
        - Main thread: GUI event loop
        - Tray thread: System tray icon
        - Hotkey thread: Global keyboard hooks
        
        All crypto operations are thread-safe via the crypto module.
    """
    
    def __init__(self) -> None:
        """Initialize the AnonIT application."""
        self.gui: Optional[AnonITGUI] = None
        self.tray_icon: Optional[pystray.Icon] = None
        self.running = True
        self._lock = threading.Lock()
        
        # Register cleanup handler for graceful shutdown
        atexit.register(self._cleanup)
        
        logger.info("AnonIT initialized")
    
    def _on_key_change(self, password: str) -> None:
        """
        Handle key change from GUI.
        
        Called when user enters a new encryption key.
        
        Args:
            password: The user-provided password.
        """
        try:
            set_encryption_key(password)
            logger.info("Encryption key activated via GUI")
        except ValueError as e:
            logger.error(f"Failed to set key: {e}")
    
    def _handle_encrypt(self, text: str) -> Optional[str]:
        """
        Encrypt text from GUI text area.
        
        Args:
            text: Plaintext to encrypt.
            
        Returns:
            Encrypted text, or None on failure.
        """
        if not has_key():
            logger.warning("Encryption attempted without key")
            return None
        
        if not text or not text.strip():
            return None
        
        try:
            result = encrypt(text)
            logger.info("Text encrypted via GUI")
            return result
        except ValueError as e:
            logger.error(f"GUI encryption failed: {e}")
            return None
    
    def _handle_decrypt(self, text: str) -> Optional[str]:
        """
        Decrypt text from GUI text area.
        
        Args:
            text: Encrypted text to decrypt.
            
        Returns:
            Decrypted plaintext, or None on failure.
        """
        if not has_key():
            logger.warning("Decryption attempted without key")
            return None
        
        if not text or not text.strip():
            return None
        
        try:
            result = decrypt(text)
            logger.info("Text decrypted via GUI")
            return result
        except ValueError as e:
            logger.error(f"GUI decryption failed: {e}")
            return None
    
    def _encrypt_selection(self) -> None:
        """
        Encrypt currently selected text via hotkey.
        
        Workflow:
        1. Clear clipboard
        2. Copy selected text (Ctrl+C)
        3. Encrypt the text
        4. Paste encrypted text (Ctrl+V)
        
        If no key is set, opens the GUI for key entry.
        """
        if not has_key():
            logger.info("No key set, opening GUI")
            self._show_gui()
            return
        
        with self._lock:
            try:
                # Small delay to let hotkey release
                time.sleep(HOTKEY_DELAY)
                
                # Clear clipboard to detect if copy succeeds
                pyperclip.copy('')
                
                # Copy selected text
                keyboard.send('ctrl+c')
                time.sleep(CLIPBOARD_DELAY)
                
                text = pyperclip.paste()
                
                if not text:
                    logger.debug("No text selected for encryption")
                    return
                
                # Don't re-encrypt already encrypted text
                if is_encrypted(text):
                    logger.debug("Text already encrypted, skipping")
                    return
                
                # Encrypt and paste
                encrypted = encrypt(text)
                pyperclip.copy(encrypted)
                keyboard.send('ctrl+v')
                
                logger.info(f"Hotkey encryption: {len(text)} -> {len(encrypted)} chars")
                
            except Exception as e:
                logger.error(f"Hotkey encryption failed: {e}")
    
    def _decrypt_selection(self) -> None:
        """
        Decrypt currently selected text via hotkey.
        
        Workflow:
        1. Clear clipboard
        2. Copy selected text (Ctrl+C)
        3. Decrypt the text
        4. Show popup with decrypted text (no replacement)
        
        If no key is set, opens the GUI for key entry.
        """
        if not has_key():
            logger.info("No key set, opening GUI")
            self._show_gui()
            return
        
        with self._lock:
            try:
                time.sleep(HOTKEY_DELAY)
                
                pyperclip.copy('')
                keyboard.send('ctrl+c')
                time.sleep(CLIPBOARD_DELAY)
                
                text = pyperclip.paste()
                
                if not text:
                    logger.debug("No text selected for decryption")
                    return
                
                if not is_encrypted(text):
                    logger.debug("Text not encrypted, skipping")
                    return
                
                decrypted = decrypt(text)
                
                # Show popup instead of replacing text
                self._show_decrypt_popup(decrypted)
                
                logger.info(f"Hotkey decryption: {len(text)} -> {len(decrypted)} chars")
                
            except Exception as e:
                logger.error(f"Hotkey decryption failed: {e}")
    
    def _show_decrypt_popup(self, text: str) -> None:
        """Show a small popup window with decrypted text in a separate thread."""
        
        def create_popup():
            from PyQt6.QtWidgets import (
                QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                QLabel, QTextEdit, QPushButton
            )
            from PyQt6.QtCore import Qt, QTimer, QSize
            from PyQt6.QtGui import QFont, QGuiApplication
            from icons import Icons
            
            app = QApplication([])
            
            # Stylesheet
            style = """
            QWidget {
                background-color: #0a0a0a;
                color: #ffffff;
                font-family: 'Segoe UI', sans-serif;
            }
            QLabel#header {
                color: #00d4aa;
                font-size: 14px;
                font-weight: bold;
            }
            QTextEdit {
                background-color: #1e1e1e;
                border: 1px solid #2a2a2a;
                border-radius: 8px;
                padding: 12px;
                color: #ffffff;
                font-family: 'Consolas', monospace;
                font-size: 12px;
                selection-background-color: #00d4aa;
            }
            QPushButton#copy {
                background-color: #00d4aa;
                color: #0a0a0a;
                border: none;
                border-radius: 6px;
                padding: 10px 24px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton#copy:hover {
                background-color: #00f5c4;
            }
            QPushButton#close {
                background-color: #2a2a2a;
                color: #888888;
                border: none;
                border-radius: 6px;
                padding: 10px 24px;
                font-size: 12px;
            }
            QPushButton#close:hover {
                background-color: #3a3a3a;
                color: #ffffff;
            }
            """
            
            popup = QWidget()
            popup.setWindowTitle("Decrypted")
            popup.setStyleSheet(style)
            popup.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.Window)
            
            # Size based on content
            width = min(max(400, len(text) * 7), 600)
            height = min(max(200, text.count('\n') * 25 + 150), 450)
            popup.resize(width, height)
            
            # Center on screen
            screen = QGuiApplication.primaryScreen().geometry()
            x = (screen.width() - width) // 2
            y = (screen.height() - height) // 2
            popup.move(x, y)
            
            layout = QVBoxLayout(popup)
            layout.setContentsMargins(20, 20, 20, 20)
            layout.setSpacing(12)
            
            # Header with icon
            header_layout = QHBoxLayout()
            header_icon = QLabel()
            header_icon.setPixmap(Icons.unlock(20, "#00d4aa").pixmap(QSize(20, 20)))
            header_layout.addWidget(header_icon)
            header = QLabel("Decrypted Message")
            header.setObjectName("header")
            header_layout.addWidget(header)
            header_layout.addStretch()
            layout.addLayout(header_layout)
            
            # Text area
            text_area = QTextEdit()
            text_area.setPlainText(text)
            text_area.setReadOnly(False)
            layout.addWidget(text_area)
            
            # Buttons
            btn_layout = QHBoxLayout()
            btn_layout.setSpacing(10)
            
            copy_btn = QPushButton(" Copy")
            copy_btn.setObjectName("copy")
            copy_btn.setIcon(Icons.copy(16, "#0a0a0a"))
            copy_btn.setIconSize(QSize(16, 16))
            copy_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            
            def copy_text():
                app.clipboard().setText(text)
                copy_btn.setIcon(Icons.check(16, "#0a0a0a"))
                copy_btn.setText(" Copied!")
                QTimer.singleShot(1000, lambda: (copy_btn.setIcon(Icons.copy(16, "#0a0a0a")), copy_btn.setText(" Copy")))
            
            copy_btn.clicked.connect(copy_text)
            btn_layout.addWidget(copy_btn)
            
            btn_layout.addStretch()
            
            close_btn = QPushButton(" Close")
            close_btn.setObjectName("close")
            close_btn.setIcon(Icons.x(16, "#888888"))
            close_btn.setIconSize(QSize(16, 16))
            close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            close_btn.clicked.connect(popup.close)
            btn_layout.addWidget(close_btn)
            
            layout.addLayout(btn_layout)
            
            # Auto-close after 30 seconds
            QTimer.singleShot(30000, popup.close)
            
            popup.show()
            app.exec()
        
        # Run popup in separate thread to not block hotkeys
        popup_thread = threading.Thread(target=create_popup, daemon=True)
        popup_thread.start()
    
    def _show_gui(self) -> None:
        """Show the GUI window."""
        if self.gui:
            self.gui.show()
    
    def _cleanup(self) -> None:
        """
        Clean up resources on application exit.
        Fast cleanup - skip slow memory operations.
        """
        logger.info("Cleaning up...")
        
        # Quick keyboard unhook first
        try:
            keyboard.unhook_all()
        except Exception:
            pass
        
        # Fast key clear (skip slow memory protection)
        try:
            clear_encryption_key()
        except Exception:
            pass
        
        logger.info("Cleanup complete")
    
    def _quit_app(self) -> None:
        """Exit the application immediately."""
        import os
        
        # Unhook keyboard first (fast)
        try:
            keyboard.unhook_all()
        except Exception:
            pass
        
        # Clear key from memory (fast)
        try:
            clear_encryption_key()
        except Exception:
            pass
        
        # Force exit immediately - skip all slow cleanup
        # pystray.stop() and PyQt6 cleanup are too slow
        os._exit(0)
    
    def _setup_hotkeys(self) -> None:
        """Register global hotkeys."""
        # trigger_on_release=True ensures the callback runs AFTER keys are released
        # This prevents conflicts with clipboard operations (ctrl+c/v) and
        # ensures modifier keys work normally in other applications
        keyboard.add_hotkey('ctrl+shift+e', self._encrypt_selection, suppress=True, trigger_on_release=True)
        keyboard.add_hotkey('ctrl+shift+d', self._decrypt_selection, suppress=True, trigger_on_release=True)
        logger.info("Global hotkeys registered")
    
    def _create_tray_menu(self) -> pystray.Menu:
        """Create the system tray context menu."""
        return pystray.Menu(
            pystray.MenuItem("Open AnonIT", lambda: self._show_gui(), default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", lambda: self._quit_app())
        )
    
    def run(self) -> None:
        """
        Start the AnonIT application.
        
        This method:
        1. Registers global hotkeys
        2. Creates the GUI
        3. Starts the system tray icon
        4. Runs the GUI event loop (blocking)
        """
        # Register hotkeys
        self._setup_hotkeys()
        
        # Create GUI
        self.gui = AnonITGUI(
            on_key_change=self._on_key_change,
            on_encrypt=self._handle_encrypt,
            on_decrypt=self._handle_decrypt
        )
        
        # Start tray icon in background thread
        def run_tray():
            try:
                icon_image = create_tray_icon(64)
                self.tray_icon = pystray.Icon(
                    "AnonIT",
                    icon_image,
                    "AnonIT - Secure Encryption",
                    self._create_tray_menu()
                )
                self.tray_icon.run()
            except Exception as e:
                logger.error(f"Tray icon error: {e}")
        
        tray_thread = threading.Thread(target=run_tray, daemon=True)
        tray_thread.start()
        
        # Print startup banner
        print("=" * 50)
        print("  AnonIT - Secure Text Encryption")
        print("=" * 50)
        print("  Hotkeys:")
        print("    Ctrl+Shift+E  →  Encrypt selected text")
        print("    Ctrl+Shift+D  →  Decrypt selected text")
        print("")
        print("  Keys are stored in memory only.")
        print("  They will be securely wiped on exit.")
        print("=" * 50)
        
        # Run GUI event loop (blocks until window closed)
        self.gui.mainloop()


def main() -> int:
    """
    Application entry point.
    
    Returns:
        Exit code (0 for success).
    """
    try:
        app = AnonIT()
        app.run()
        return 0
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        return 0
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
