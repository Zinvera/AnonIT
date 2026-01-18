#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AnonIT - Secure Text Encryption Tool
"""

__version__ = "1.4.2"

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
        import tkinter as tk
        from tkinter import scrolledtext
        
        def show_popup():
            root = tk.Tk()
            root.title("🔓 Decrypted")
            root.configure(bg='#0a0a0a')
            root.geometry("800x800")
            root.attributes('-topmost', True)
            
            # Center on screen
            root.update_idletasks()
            x = (root.winfo_screenwidth() - 800) // 2
            y = (root.winfo_screenheight() - 800) // 2
            root.geometry(f"+{x}+{y}")
            
            # Header
            header = tk.Label(root, text="🔓 Decrypted Message", 
                             font=('Segoe UI', 14, 'bold'),
                             fg='#00d4aa', bg='#0a0a0a')
            header.pack(pady=(20, 10), padx=20, anchor='w')
            
            # Text area container (for border)
            text_frame = tk.Frame(root, bg='#2a2a2a', padx=1, pady=1)
            text_frame.pack(padx=20, pady=(0, 20), fill='both', expand=True)
            
            text_area = scrolledtext.ScrolledText(text_frame, wrap=tk.WORD,
                                                   font=('Consolas', 11),
                                                   bg='#141414', fg='#ffffff',
                                                   insertbackground='#ffffff',
                                                   selectbackground='#00d4aa',
                                                   relief='flat', bd=10)
            text_area.pack(fill='both', expand=True)
            text_area.insert('1.0', text)
            # Make read-only after insert if desired, but editable is usually fine for copying
            
            # Button frame
            btn_frame = tk.Frame(root, bg='#0a0a0a')
            btn_frame.pack(padx=20, pady=(0, 20), fill='x')
            
            def copy_text():
                try:
                    pyperclip.copy(text)
                except Exception as e:
                    logger.error(f"Clipboard error: {e}")
                    # Fallback
                    root.clipboard_clear()
                    root.clipboard_append(text)
                    root.update()
                
                copy_btn.config(text="✓ Copied!")
                root.after(1500, lambda: copy_btn.config(text="📋 Copy"))
            
            copy_btn = tk.Button(btn_frame, text="📋 Copy", command=copy_text,
                                font=('Segoe UI', 10, 'bold'),
                                bg='#00d4aa', fg='#0a0a0a',
                                activebackground='#00f5c4', activeforeground='#0a0a0a',
                                relief='flat', padx=20, pady=8,
                                cursor='hand2')
            copy_btn.pack(side='left')
            
            close_btn = tk.Button(btn_frame, text="✕ Close", command=root.destroy,
                                 font=('Segoe UI', 10),
                                 bg='#1e1e1e', fg='#aaaaaa',
                                 activebackground='#2a2a2a', activeforeground='#ffffff',
                                 relief='flat', padx=20, pady=8,
                                 cursor='hand2')
            close_btn.pack(side='right')
            
            root.after(60000, root.destroy)
            root.mainloop()
        
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
