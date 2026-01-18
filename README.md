# AnonIT

> **Privacy on top of every messenger.**

A simple encryption tool with a modern dark-themed GUI and F8 hotkey. WhatsApp, Discord, Telegram, Instagram DMs — doesn't matter. Your messages, your encryption, your keys.

I built this because I wanted a quick way to encrypt sensitive info without relying on third-party websites.

## What it does

- **F8 hotkey** — Select text anywhere, press F8:
  - Normal text → gets encrypted and pasted back
  - Encrypted text → gets decrypted (shown in popup)
- GUI for manual encrypt/decrypt
- Runs quietly in your system tray

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
3. Select any text and press **F8**:
   - Plain text → encrypted and pasted
   - Encrypted text → decrypted and shown in popup

The app sits in your system tray when minimized.

## Building from source

```bash
pip install pyinstaller
pyinstaller AnonIT.spec --clean
```

The exe will be in the `dist` folder.

## Requirements

- Python 3.8+
- Windows

## Dependencies

- `pycryptodome` - AES encryption
- `argon2-cffi` - Key derivation
- `keyboard` - F8 hotkey
- `pyperclip` - Clipboard access
- `pystray` - System tray icon
- `Pillow` - Icon rendering
- `PyQt6` - Modern GUI

## License

MIT - do whatever you want with it.

---

Made because copy-pasting into encryption websites felt sketchy.
