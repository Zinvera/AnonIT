# AnonIT Server

Secure WebSocket server for AnonIT Messenger.

## Security Guarantees

- **End-to-End Encryption**: Server NEVER sees plaintext messages
- **No IP Logging**: Privacy by design
- **No Metadata Storage**: Only encrypted message blobs
- **Auto-Expiry**: Messages deleted after 72 hours
- **Rate Limiting**: Protection against abuse

## Quick Start

### Option 1: Docker (Recommended)

```bash
docker-compose up -d
```

### Option 2: Manual

```bash
# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Linux/Mac)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run server
python server.py
```

### Option 3: Linux Service

```bash
sudo ./install.sh
```

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `ANONIT_HOST` | `0.0.0.0` | Bind address |
| `ANONIT_PORT` | `8765` | WebSocket port |
| `ANONIT_DATA` | `./data` | Data directory |
| `ANONIT_LOG_LEVEL` | `INFO` | Log level |

## Deployment

### With Nginx (TLS)

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
        proxy_set_header Host $host;
        proxy_read_timeout 86400;
    }
}
```

### With Tor Hidden Service

Add to `/etc/tor/torrc`:

```
HiddenServiceDir /var/lib/tor/anonit/
HiddenServicePort 8765 127.0.0.1:8765
```

## Client Connection

```python
# In AnonIT client
python main.py --server wss://your-domain.com
# or for Tor
python main.py --server ws://your-onion-address.onion:8765
```

## License

MIT
