#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AnonIT - Dark Theme GUI
========================

Simple, clean dark-themed interface for secure text encryption.
Built with standard Tkinter for maximum compatibility.

Author: AnonIT Project
License: MIT
"""

import logging
import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional

from PIL import ImageTk

logger = logging.getLogger(__name__)

# Color scheme
COLORS = {
    'bg_dark': '#0a0a0a',
    'bg_medium': '#141414',
    'bg_light': '#1e1e1e',
    'accent': '#00d4aa',
    'accent_hover': '#00f5c4',
    'text': '#ffffff',
    'text_dim': '#888888',
    'border': '#2a2a2a',
    'error': '#ff4757',
    'success': '#00d4aa'
}


class AnonITGUI:
    """
    Main GUI window for AnonIT encryption tool.
    
    Provides:
        - Key input with visibility toggle
        - Text area for manual encryption/decryption
        - Status bar showing key state
    
    Args:
        on_key_change: Called when user sets a new encryption key.
        on_encrypt: Called to encrypt text, returns encrypted string.
        on_decrypt: Called to decrypt text, returns decrypted string.
    """
    
    def __init__(self, 
                 on_key_change: Optional[Callable[[str], None]] = None,
                 on_encrypt: Optional[Callable[[str], Optional[str]]] = None,
                 on_decrypt: Optional[Callable[[str], Optional[str]]] = None):
        self.window: Optional[tk.Tk] = None
        self.on_key_change = on_key_change
        self.on_encrypt = on_encrypt
        self.on_decrypt = on_decrypt
        
    def show(self) -> None:
        """Show the GUI window, creating it if necessary."""
        if self.window is not None:
            try:
                self.window.deiconify()
                self.window.lift()
                return
            except tk.TclError:
                self.window = None
                
        self._create_window()
        
    def _create_window(self) -> None:
        """Create the main window with dark theme."""
        self.window = tk.Tk()
        self.window.title("AnonIT")
        self.window.geometry("550x480")
        self.window.configure(bg=COLORS['bg_dark'])
        self.window.resizable(True, True)
        
        # Set window icon
        try:
            from icon import create_icon
            icon_img = create_icon(32)
            self._icon_photo = ImageTk.PhotoImage(icon_img)
            self.window.iconphoto(True, self._icon_photo)
        except Exception as e:
            logger.warning(f"Could not set icon: {e}")
        
        # Configure styles
        self._setup_styles()
        
        # Build UI
        self._create_header()
        self._create_key_section()
        self._create_text_section()
        self._create_buttons()
        self._create_status_bar()
        
        # Handle close
        self.window.protocol("WM_DELETE_WINDOW", self._on_close)
        
        logger.info("GUI window created")


    def _setup_styles(self) -> None:
        """Configure ttk styles for dark theme."""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Frame styles
        style.configure('Dark.TFrame', background=COLORS['bg_dark'])
        
        # Label styles
        style.configure('Dark.TLabel', 
                       background=COLORS['bg_dark'], 
                       foreground=COLORS['text'],
                       font=('Segoe UI', 10))
        style.configure('Header.TLabel',
                       background=COLORS['bg_dark'],
                       foreground=COLORS['accent'],
                       font=('Segoe UI', 24, 'bold'))
        style.configure('Subtitle.TLabel',
                       background=COLORS['bg_dark'],
                       foreground=COLORS['text_dim'],
                       font=('Segoe UI', 9))

    def _create_header(self) -> None:
        """Create the header section with title."""
        header_frame = ttk.Frame(self.window, style='Dark.TFrame')
        header_frame.pack(fill='x', padx=20, pady=(20, 10))
        
        title = ttk.Label(header_frame, text="AnonIT", style='Header.TLabel')
        title.pack(anchor='w')
        
        subtitle = ttk.Label(
            header_frame, 
            text="Secure AES-256 Encryption • Keys stored in memory only",
            style='Subtitle.TLabel'
        )
        subtitle.pack(anchor='w')

    def _create_key_section(self) -> None:
        """Create the encryption key input section."""
        key_frame = ttk.Frame(self.window, style='Dark.TFrame')
        key_frame.pack(fill='x', padx=20, pady=10)
        
        key_label = ttk.Label(key_frame, text="Encryption Key", style='Dark.TLabel')
        key_label.pack(anchor='w', pady=(0, 5))
        
        # Key input row
        input_row = ttk.Frame(key_frame, style='Dark.TFrame')
        input_row.pack(fill='x')
        
        self.key_var = tk.StringVar()
        self.key_entry = tk.Entry(
            input_row, 
            textvariable=self.key_var,
            show="•",
            font=('Segoe UI', 11),
            bg=COLORS['bg_medium'],
            fg=COLORS['text'],
            insertbackground=COLORS['accent'],
            relief='flat',
            highlightthickness=1,
            highlightbackground=COLORS['border'],
            highlightcolor=COLORS['accent']
        )
        self.key_entry.pack(side='left', fill='x', expand=True, ipady=8)
        self.key_entry.bind('<Return>', lambda e: self._set_key())
        
        # Show/hide button
        self.show_key_var = tk.BooleanVar(value=False)
        show_btn = tk.Button(
            input_row, 
            text="👁", 
            command=self._toggle_key_visibility,
            bg=COLORS['bg_light'],
            fg=COLORS['text'],
            relief='flat',
            font=('Segoe UI', 12),
            cursor='hand2'
        )
        show_btn.pack(side='left', padx=(5, 0), ipady=4, ipadx=8)
        
        set_btn = tk.Button(
            input_row, 
            text="Set Key",
            command=self._set_key,
            bg=COLORS['accent'],
            fg=COLORS['bg_dark'],
            relief='flat',
            font=('Segoe UI', 10, 'bold'),
            cursor='hand2'
        )
        set_btn.pack(side='left', padx=(5, 0), ipady=6, ipadx=12)

    def _create_text_section(self) -> None:
        """Create the text input/output section."""
        text_frame = ttk.Frame(self.window, style='Dark.TFrame')
        text_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        text_label = ttk.Label(text_frame, text="Text", style='Dark.TLabel')
        text_label.pack(anchor='w', pady=(0, 5))
        
        # Text area with border
        text_container = tk.Frame(text_frame, bg=COLORS['border'])
        text_container.pack(fill='both', expand=True)
        
        self.text_area = tk.Text(
            text_container,
            wrap='word',
            font=('Consolas', 11),
            bg=COLORS['bg_medium'],
            fg=COLORS['text'],
            insertbackground=COLORS['accent'],
            relief='flat',
            padx=10,
            pady=10,
            highlightthickness=0
        )
        self.text_area.pack(fill='both', expand=True, padx=1, pady=1)
        
        # Scrollbar
        scrollbar = tk.Scrollbar(
            self.text_area, 
            command=self.text_area.yview,
            bg=COLORS['bg_light'],
            troughcolor=COLORS['bg_medium'],
            highlightthickness=0
        )
        scrollbar.pack(side='right', fill='y')
        self.text_area.config(yscrollcommand=scrollbar.set)

    def _create_buttons(self) -> None:
        """Create the action buttons."""
        btn_frame = ttk.Frame(self.window, style='Dark.TFrame')
        btn_frame.pack(fill='x', padx=20, pady=10)
        
        encrypt_btn = tk.Button(
            btn_frame, 
            text="🔒 Encrypt",
            command=self._encrypt_text,
            bg=COLORS['accent'],
            fg=COLORS['bg_dark'],
            relief='flat',
            font=('Segoe UI', 11, 'bold'),
            cursor='hand2'
        )
        encrypt_btn.pack(side='left', ipady=8, ipadx=20)
        
        decrypt_btn = tk.Button(
            btn_frame,
            text="🔓 Decrypt",
            command=self._decrypt_text,
            bg=COLORS['bg_light'],
            fg=COLORS['text'],
            relief='flat',
            font=('Segoe UI', 11),
            cursor='hand2'
        )
        decrypt_btn.pack(side='left', padx=(10, 0), ipady=8, ipadx=20)
        
        clear_btn = tk.Button(
            btn_frame,
            text="Clear",
            command=self._clear_text,
            bg=COLORS['bg_light'],
            fg=COLORS['text_dim'],
            relief='flat',
            font=('Segoe UI', 10),
            cursor='hand2'
        )
        clear_btn.pack(side='right', ipady=6, ipadx=15)

    def _create_status_bar(self) -> None:
        """Create the status bar."""
        status_frame = tk.Frame(self.window, bg=COLORS['bg_light'])
        status_frame.pack(fill='x', side='bottom')
        
        self.status_var = tk.StringVar(value="Ready • Ctrl+Shift+E to encrypt • Ctrl+Shift+D to decrypt")
        status_label = tk.Label(
            status_frame,
            textvariable=self.status_var,
            bg=COLORS['bg_light'],
            fg=COLORS['text_dim'],
            font=('Segoe UI', 9),
            pady=8
        )
        status_label.pack(side='left', padx=10)
        
        # Key status indicator
        self.key_status_var = tk.StringVar(value="● No key set")
        self.key_status = tk.Label(
            status_frame,
            textvariable=self.key_status_var,
            bg=COLORS['bg_light'],
            fg=COLORS['error'],
            font=('Segoe UI', 9)
        )
        self.key_status.pack(side='right', padx=10)

    def _toggle_key_visibility(self) -> None:
        """Toggle key visibility."""
        self.show_key_var.set(not self.show_key_var.get())
        self.key_entry.config(show="" if self.show_key_var.get() else "•")

    def _set_key(self) -> None:
        """Set the encryption key."""
        key = self.key_var.get()
        if not key:
            self.status_var.set("⚠ Please enter an encryption key")
            return
        if len(key) < 4:
            self.status_var.set("⚠ Key must be at least 4 characters")
            return
        
        # Call the callback
        if self.on_key_change:
            self.on_key_change(key)
        
        # Update UI
        self.key_status_var.set("● Key active")
        self.key_status.config(fg=COLORS['success'])
        self.status_var.set("Encryption key set successfully")
        
        # Clear key from entry for security
        self.key_var.set("")
        self.key_entry.config(show="•")
        
        logger.info("Key set via GUI")

    def _encrypt_text(self) -> None:
        """Encrypt the text in the text area."""
        text = self.text_area.get("1.0", "end-1c")
        if not text.strip():
            self.status_var.set("⚠ No text to encrypt")
            return
        
        if self.on_encrypt:
            result = self.on_encrypt(text)
            if result:
                self.text_area.delete("1.0", "end")
                self.text_area.insert("1.0", result)
                self.status_var.set("Text encrypted successfully")
            else:
                self.status_var.set("⚠ Encryption failed - is key set?")
        else:
            self.status_var.set("⚠ Encryption not available")

    def _decrypt_text(self) -> None:
        """Decrypt the text in the text area."""
        text = self.text_area.get("1.0", "end-1c")
        if not text.strip():
            self.status_var.set("⚠ No text to decrypt")
            return
        
        if self.on_decrypt:
            result = self.on_decrypt(text)
            if result:
                self.text_area.delete("1.0", "end")
                self.text_area.insert("1.0", result)
                self.status_var.set("Text decrypted successfully")
            else:
                self.status_var.set("⚠ Decryption failed - wrong key?")
        else:
            self.status_var.set("⚠ Decryption not available")

    def _clear_text(self) -> None:
        """Clear the text area."""
        self.text_area.delete("1.0", "end")
        self.status_var.set("Ready")

    def _on_close(self) -> None:
        """Hide window instead of closing."""
        self.window.withdraw()

    def run(self) -> None:
        """Start the GUI mainloop."""
        if self.window:
            self.window.mainloop()
    
    def mainloop(self) -> None:
        """Alias for run() - compatibility with CTk."""
        self.show()
        self.run()
    
    def quit(self) -> None:
        """Quit the application."""
        if self.window:
            self.window.quit()


# Standalone testing
if __name__ == "__main__":
    def test_encrypt(text):
        return f"ANON[test:{len(text)}chars]"
    
    def test_decrypt(text):
        return "Decrypted content"
    
    gui = AnonITGUI(
        on_key_change=lambda k: print(f"Key: {k[:3]}..."),
        on_encrypt=test_encrypt,
        on_decrypt=test_decrypt
    )
    gui.mainloop()
