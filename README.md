<p align="center">
  <img src="iconmain.png" alt="AnonIT Logo" width="120" height="120">
</p>

<h1 align="center">AnonIT</h1>

<p align="center">
  <strong>🔐 Universal Text Encryption for Any Messenger</strong>
</p>

<p align="center">
  <a href="https://github.com/Zinvera/AnonIT/releases"><img src="https://img.shields.io/github/v/release/Zinvera/AnonIT?style=flat-square&color=blue" alt="Release"></a>
  <a href="https://github.com/Zinvera/AnonIT/blob/main/LICENSE"><img src="https://img.shields.io/github/license/Zinvera/AnonIT?style=flat-square&color=green" alt="License MIT"></a>
  <a href="https://github.com/Zinvera/AnonIT/releases"><img src="https://img.shields.io/github/downloads/Zinvera/AnonIT/total?style=flat-square&color=brightgreen" alt="Downloads"></a>
  <a href="https://github.com/Zinvera/AnonIT/stargazers"><img src="https://img.shields.io/github/stars/Zinvera/AnonIT?style=flat-square&color=yellow" alt="Stars"></a>
  <img src="https://img.shields.io/badge/platform-Windows-blue?style=flat-square" alt="Platform Windows">
  <img src="https://img.shields.io/badge/python-3.8+-blue?style=flat-square" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/encryption-AES--256--GCM-green?style=flat-square" alt="AES-256-GCM">
</p>

<p align="center">
  <b>Encrypt any text with one hotkey — OR — run your own secure messenger server.</b><br>
  <sub>Works with WhatsApp, Discord, Telegram, Signal, Instagram DMs — any app. 100% Open Source.</sub>
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-features">Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#%EF%B8%8F-self-hosted-messenger">Self-Hosted Messenger</a> •
  <a href="#-security">Security</a> •
  <a href="#-faq">FAQ</a>
</p>

---

## 🎯 Why AnonIT?

| Problem | AnonIT Solution |
|---------|-----------------|
| ❌ Messengers can read your messages | ✅ End-to-end encryption YOU control |
| ❌ Online encryption tools are sketchy | ✅ 100% offline, open-source |
| ❌ Encryption is complicated | ✅ One hotkey: **F8** |
| ❌ Keys stored insecurely | ✅ Keys exist only in RAM, wiped on exit |

**Stop trusting third parties with your sensitive data.** AnonIT gives you military-grade encryption (AES-256-GCM) that works on top of ANY messaging platform.

---

## ⚡ Quick Start

```bash
# Option 1: Download ready-to-use executable
# → https://github.com/Zinvera/AnonIT/releases

# Option 2: Run from source
pip install -r requirements.txt
python main.py
```

**That's it!** Enter your encryption key, select text anywhere, press **F8**.

---

## ✨ Features

### 🔑 One-Hotkey Encryption
- **Select text → Press F8 → Done**
- Plain text gets encrypted and auto-pasted
- Encrypted text gets decrypted (shown in secure popup)

### 🌐 Universal Compatibility
Works with **any application** that supports text:
- 💬 **Messengers**: WhatsApp, Telegram, Discord, Signal, Instagram DMs
- 📧 **Email**: Gmail, Outlook, ProtonMail
- 📝 **Notes**: Notion, Obsidian, OneNote
- 💻 **Anywhere**: Browsers, text editors, any input field

### 🖥️ Modern Dark GUI
- Clean PyQt6 interface
- Manual encrypt/decrypt mode
- System tray integration — runs silently in background

### 🔒 Zero-Trust Security
- **AES-256-GCM** — Military-grade authenticated encryption
- **Argon2id** — GPU-resistant key derivation (winner of Password Hashing Competition)
- **Memory-only keys** — Never written to disk
- **Auto-wipe** — Keys cleared when app closes

### 💬 Built-in Secure Messenger
- **Self-hosted server** — Run your own infrastructure
- **End-to-end encrypted** — Server never sees plaintext
- **No metadata logging** — Zero IP/user tracking
- **Panic button** — Instant wipe of all data
- **Docker support** — Deploy in minutes

---

## 📦 Installation

### Prerequisites
- Windows 10/11
- Python 3.8+ (for source installation)

### Option 1: Executable (Recommended)

Download the latest `.exe` from [**Releases**](https://github.com/Zinvera/AnonIT/releases) — no installation required.

### Option 2: From Source

```bash
# Clone repository
git clone https://github.com/Zinvera/AnonIT.git
cd AnonIT

# Install dependencies
pip install -r requirements.txt

# Run
python main.py
```

### Option 3: Build Executable

```bash
pip install pyinstaller
pyinstaller AnonIT.spec --clean
# Output: dist/AnonIT.exe
```

---

## 🖥️ Self-Hosted Messenger

AnonIT includes a complete secure messaging system. Host your own server — **you control everything**.

### Why Self-Host?

| Public Messengers | AnonIT Self-Hosted |
|-------------------|-------------------|
| ❌ Company controls servers | ✅ YOU control the server |
| ❌ Metadata logged | ✅ Zero logging by design |
| ❌ Trust third parties | ✅ Trust no one but yourself |
| ❌ Can be shut down | ✅ Your infrastructure |

### Server Features

- 🔐 **End-to-end encryption** — Server NEVER sees plaintext
- 🚫 **No IP logging** — Privacy by design
- ⏰ **Auto-expiry** — Messages deleted after 72 hours
- 🚨 **Panic button** — Instant wipe of all user data
- 🐳 **Docker ready** — One command deployment
- 🧅 **Tor compatible** — Run as hidden service

### Quick Server Setup

#### Option 1: Docker (Recommended)

```bash
cd AnonIT-Server
docker-compose up -d
```

#### Option 2: Manual

```bash
cd AnonIT-Server
pip install -r requirements.txt
python server.py
```

#### Option 3: Linux Service

```bash
cd AnonIT-Server
sudo ./install.sh
```

### Server Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `ANONIT_HOST` | `0.0.0.0` | Bind address |
| `ANONIT_PORT` | `8765` | WebSocket port |
| `ANONIT_DATA` | `./data` | Data directory |
| `ANONIT_LOG_LEVEL` | `INFO` | Log level |

### Production Deployment

#### With Nginx + TLS

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }
}
```

#### As Tor Hidden Service

```bash
# Add to /etc/tor/torrc
HiddenServiceDir /var/lib/tor/anonit/
HiddenServicePort 8765 127.0.0.1:8765
```

### Connect Client to Your Server

```bash
python main.py --server wss://your-domain.com
# or for Tor
python main.py --server ws://your-onion-address.onion:8765
```

---

## 🔧 How It Works

```
┌─────────────────────────────────────────────────────────────┐
│  1. Enter your secret key in AnonIT                         │
│  2. Select any text in any application                      │
│  3. Press F8                                                 │
│     ├─ Plain text?    → Encrypted & pasted back             │
│     └─ Encrypted?     → Decrypted & shown in popup          │
│  4. Share encrypted text via any messenger                  │
│  5. Recipient with same key presses F8 to decrypt           │
└─────────────────────────────────────────────────────────────┘
```

### Encryption Flow
```
Your Message → Argon2id(Key) → AES-256-GCM → Base64 → Clipboard
```

### Decryption Flow
```
Encrypted Text → Base64 → AES-256-GCM → Argon2id(Key) → Original Message
```

---

## 🛡️ Security

### Cryptographic Standards

| Component | Algorithm | Why |
|-----------|-----------|-----|
| **Encryption** | AES-256-GCM | Authenticated encryption, NIST approved |
| **Key Derivation** | Argon2id | Winner of PHC, resistant to GPU/ASIC attacks |
| **Encoding** | Base64 | Safe for any text field |

### Security Guarantees

- ✅ **No network access** — 100% offline operation
- ✅ **No key storage** — Keys exist only in RAM
- ✅ **No telemetry** — Zero data collection
- ✅ **Open source** — Audit the code yourself
- ✅ **Memory wiping** — Sensitive data cleared on exit

### What AnonIT Does NOT Protect Against

- Keyloggers on your system
- Screen capture malware
- Physical access to unlocked device
- Weak passwords/keys

---

## 📋 Dependencies

| Package | Purpose |
|---------|---------|
| `pycryptodome` | AES-256-GCM encryption |
| `argon2-cffi` | Argon2id key derivation |
| `keyboard` | Global F8 hotkey |
| `pyperclip` | Clipboard operations |
| `pystray` | System tray icon |
| `Pillow` | Icon rendering |
| `PyQt6` | Modern GUI framework |

---

## ❓ FAQ

<details>
<summary><b>Is this safer than WhatsApp's built-in encryption?</b></summary>

WhatsApp uses end-to-end encryption, but Meta controls the keys and implementation. With AnonIT, YOU control the encryption — even if WhatsApp is compromised, your messages remain encrypted with your personal key.
</details>

<details>
<summary><b>Can I use different keys for different contacts?</b></summary>

Yes! Simply change the key in the GUI before encrypting. Share different keys with different people for compartmentalized security.
</details>

<details>
<summary><b>What happens if I forget my key?</b></summary>

Messages encrypted with a lost key cannot be recovered. This is by design — there's no backdoor.
</details>

<details>
<summary><b>Does this work on Mac/Linux?</b></summary>

Currently Windows only for the client. The server runs on any platform (Linux recommended for production). Cross-platform client support is planned.
</details>

<details>
<summary><b>How do I set up my own server?</b></summary>

See the [Self-Hosted Messenger](#%EF%B8%8F-self-hosted-messenger) section. The quickest way is Docker: `cd AnonIT-Server && docker-compose up -d`
</details>

<details>
<summary><b>Is the encryption quantum-resistant?</b></summary>

AES-256 is considered quantum-resistant for symmetric encryption. However, if quantum computing concerns you, use longer keys and stay updated on post-quantum cryptography developments.
</details>

---

## 🗺️ Roadmap

- [x] Core encryption/decryption
- [x] F8 hotkey integration
- [x] System tray support
- [x] Modern dark GUI
- [x] Self-hosted messenger server
- [x] Docker deployment
- [x] Tor hidden service support
- [ ] Cross-platform support (Mac, Linux)
- [ ] Multiple key profiles
- [ ] File encryption
- [ ] Mobile apps (Android/iOS)

---

## 🤝 Contributing

Contributions are welcome! Here's how:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Good First Issues
Look for issues labeled `good first issue` or `help wanted`.

---

## 📄 License

[MIT License](LICENSE) — Use it however you want.

---

## ⭐ Star History

If AnonIT helps you, consider giving it a star! It helps others discover the project.

[![Star History Chart](https://api.star-history.com/svg?repos=Zinvera/AnonIT&type=Date)](https://star-history.com/#Zinvera/AnonIT&Date)

---

<p align="center">
  <b>Built because copy-pasting into encryption websites felt sketchy.</b>
</p>

<p align="center">
  <a href="https://github.com/Zinvera/AnonIT/issues">Report Bug</a> •
  <a href="https://github.com/Zinvera/AnonIT/issues">Request Feature</a>
</p>
