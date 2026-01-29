#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AnonIT Server Configuration
"""

import os
from pathlib import Path

# Server Settings
HOST = os.getenv("ANONIT_HOST", "0.0.0.0")
PORT = int(os.getenv("ANONIT_PORT", "8765"))

# Security
MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB max message
MAX_PENDING_MESSAGES = 1000     # Per user
MESSAGE_EXPIRY_HOURS = 72       # Delete after 72h

# Database
DATA_DIR = Path(os.getenv("ANONIT_DATA", "./data"))
DATABASE_PATH = DATA_DIR / "messages.db"

# Rate Limiting
RATE_LIMIT_MESSAGES = 60        # Messages per minute
RATE_LIMIT_CONNECTIONS = 10     # New connections per minute per IP

# Logging
LOG_LEVEL = os.getenv("ANONIT_LOG_LEVEL", "INFO")
LOG_FILE = DATA_DIR / "server.log"

# No metadata logging for privacy
LOG_IPS = False
LOG_USER_IDS = False
