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
        4. Paste decrypted text (Ctrl+V)
        
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
                pyperclip.copy(decrypted)
                keyboard.send('ctrl+v')
                
                logger.info(f"Hotkey decryption: {len(text)} -> {len(decrypted)} chars")
                
            except Exception as e:
                logger.error(f"Hotkey decryption failed: {e}")
    
    def _show_gui(self) -> None:
        """Show the GUI window."""
        if self.gui:
            self.gui.show()
    
    def _cleanup(self) -> None:
        """
        Clean up resources on application exit.
        
        Ensures:
        - Encryption keys are securely wiped
        - Keyboard hooks are removed
        - Tray icon is removed
        """
        logger.info("Cleaning up...")
        
        try:
            clear_encryption_key()
        except Exception as e:
            logger.error(f"Key cleanup error: {e}")
        
        try:
            keyboard.unhook_all()
        except Exception as e:
            logger.error(f"Keyboard cleanup error: {e}")
        
        logger.info("Cleanup complete")
    
    def _quit_app(self) -> None:
        """Exit the application gracefully."""
        logger.info("Shutting down...")
        self.running = False
        self._cleanup()
        
        if self.tray_icon:
            try:
                self.tray_icon.stop()
            except Exception:
                pass
        
        if self.gui:
            try:
                self.gui.quit()
            except Exception:
                pass
    
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
