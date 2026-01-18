#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AnonIT - Secure Text Encryption Tool
=====================================

A secure encryption utility with a modern dark-themed GUI.

Features:
    - AES-256-GCM authenticated encryption
    - Argon2id password-based key derivation
    - System tray integration
    - Modern dark-themed GUI

Usage:
    1. Start the application
    2. Enter your encryption key in the GUI
    3. Use the GUI to encrypt and decrypt text

Security Notes:
    - Keys are stored only in memory, never on disk
    - Memory is protected using Windows DPAPI when available
    - Keys are securely wiped on application exit

Author: AnonIT Project
License: MIT
Version: 1.1.0
"""

import atexit
import logging
import sys
import threading
import time
from typing import Optional

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


class AnonIT:
    """
    Main application controller for AnonIT.
    
    Coordinates between:
    - GUI window for key entry and encryption/decryption
    - System tray icon for background operation
    
    Attributes:
        gui: The main GUI window instance.
        tray_icon: System tray icon for background access.
        running: Flag indicating if application is running.
    
    Thread Safety:
        The application runs multiple threads:
        - Main thread: GUI event loop
        - Tray thread: System tray icon
        
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
        
        # Fast key clear (skip slow memory protection)
        try:
            clear_encryption_key()
        except Exception:
            pass
        
        logger.info("Cleanup complete")
    
    def _quit_app(self) -> None:
        """Exit the application immediately."""
        import os
        
        # Clear key from memory (fast)
        try:
            clear_encryption_key()
        except Exception:
            pass
        
        # Force exit immediately - skip all slow cleanup
        # pystray.stop() and PyQt6 cleanup are too slow
        os._exit(0)
    
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
        1. Creates the GUI
        2. Starts the system tray icon
        3. Runs the GUI event loop (blocking)
        """
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
        print("  Use the GUI to encrypt and decrypt text.")
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
