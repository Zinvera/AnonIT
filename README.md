# AnonIT

> **Privacy on top of every messenger.**

A simple encryption tool that lets you encrypt and decrypt text anywhere on your system using hotkeys. WhatsApp, Discord, Telegram, Instagram DMs — doesn't matter. Your messages, your encryption, your keys.

I built this because I wanted a quick way to encrypt sensitive info without opening a separate app every time. Just select text, hit a hotkey, done.

## What it does

- **Ctrl+Shift+E** → Encrypts selected text
- **Ctrl+Shift+D** → Decrypts selected text

Works in any application - browsers, text editors, chat apps, wherever you can select text.

## Security

- AES-256-GCM encryption (the good stuff)
- Argon2id for key derivation (resistant to GPU attacks)
- Keys only exist in memory, never written to disk
- Keys are wiped when you close the app

## Installation

```bash
pip install -r requirements.txt
python main.py
```

Or grab the pre-built exe from [Releases](https://github.com/Zinvera/AnonIT/releases).

## How to use

1. Start AnonIT
2. Enter your encryption key in the GUI
3. Select any text and press **Ctrl+Shift+E** to encrypt
4. Select encrypted text and press **Ctrl+Shift+D** to decrypt

The app sits in your system tray when minimized.

## Building from source

```bash
pip install pyinstaller
pyinstaller AnonIT.spec --clean
```

The exe will be in the `dist` folder.

## Requirements

- Python 3.8+
- Windows (uses Windows-specific keyboard hooks)

## Dependencies

- `pycryptodome` - AES encryption
- `argon2-cffi` - Key derivation
- `keyboard` - Global hotkeys
- `pyperclip` - Clipboard access
- `pystray` - System tray icon
- `Pillow` - Icon rendering

## License

MIT - do whatever you want with it.

---

Made because copy-pasting into encryption websites felt sketchy.
