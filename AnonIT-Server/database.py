#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AnonIT Server Storage - MAXIMUM SECURITY In-Memory Only

Privacy guarantees:
- NOTHING written to disk EVER
- All data in RAM only
- Secure wipe on deletion (overwrite with zeros)
- Panic button support
- Auto-cleanup of expired data
"""

import threading
import time
import gc
import ctypes
from typing import List, Optional, Tuple, Dict
from dataclasses import dataclass, field
from collections import defaultdict

import config


def secure_wipe_bytes(data: bytearray) -> None:
    """Securely wipe bytes from memory."""
    if not data:
        return
    try:
        # Overwrite with zeros
        for i in range(len(data)):
            data[i] = 0
        # Overwrite with ones
        for i in range(len(data)):
            data[i] = 0xFF
        # Final zero
        for i in range(len(data)):
            data[i] = 0
    except:
        pass


@dataclass
class PendingMessage:
    """A pending message - stores as bytearray for secure wipe."""
    id: int
    recipient_id: str
    sender_id: str
    encrypted_data: bytearray  # Mutable for secure wipe
    created_at: float
    expires_at: float
    
    def secure_delete(self):
        """Securely wipe message data."""
        secure_wipe_bytes(self.encrypted_data)
        self.encrypted_data = bytearray()
        self.recipient_id = ""
        self.sender_id = ""


@dataclass
class UserKeys:
    """User's public keys - stored as bytearray for secure wipe."""
    user_id: str
    public_key: bytearray
    identity_key: bytearray
    signed_prekey: bytearray
    prekey_signature: bytearray
    updated_at: float
    
    def secure_delete(self):
        """Securely wipe all key data."""
        secure_wipe_bytes(self.public_key)
        secure_wipe_bytes(self.identity_key)
        secure_wipe_bytes(self.signed_prekey)
        secure_wipe_bytes(self.prekey_signature)
        self.public_key = bytearray()
        self.identity_key = bytearray()
        self.signed_prekey = bytearray()
        self.prekey_signature = bytearray()
        self.user_id = ""


class MessageDatabase:
    """
    MAXIMUM SECURITY In-Memory storage.
    
    - NO disk writes
    - Secure memory wiping
    - Panic button support
    - Auto-expiry
    """
    
    def __init__(self, db_path=None):
        self._lock = threading.RLock()
        self._message_counter = 0
        
        self._pending_messages: Dict[str, List[PendingMessage]] = defaultdict(list)
        self._user_keys: Dict[str, UserKeys] = {}
    
    def store_message(self, recipient_id: str, sender_id: str, 
                      encrypted_data: bytes) -> int:
        """Store an encrypted message."""
        with self._lock:
            now = time.time()
            expires = now + (config.MESSAGE_EXPIRY_HOURS * 3600)
            
            self._message_counter += 1
            msg = PendingMessage(
                id=self._message_counter,
                recipient_id=recipient_id,
                sender_id=sender_id,
                encrypted_data=bytearray(encrypted_data),  # Copy to mutable
                created_at=now,
                expires_at=expires
            )
            
            # Limit check
            if len(self._pending_messages[recipient_id]) >= config.MAX_PENDING_MESSAGES:
                # Secure delete oldest
                old_msgs = self._pending_messages[recipient_id][:100]
                for old in old_msgs:
                    old.secure_delete()
                self._pending_messages[recipient_id] = \
                    self._pending_messages[recipient_id][100:]
            
            self._pending_messages[recipient_id].append(msg)
            return msg.id
    
    def get_pending_messages(self, user_id: str) -> List[Tuple[int, str, bytes]]:
        """Retrieve pending messages."""
        with self._lock:
            messages = self._pending_messages.get(user_id, [])
            return [(m.id, m.sender_id, bytes(m.encrypted_data)) for m in messages]
    
    def delete_message(self, message_id: int):
        """Securely delete a message."""
        with self._lock:
            for user_id, messages in list(self._pending_messages.items()):
                for msg in messages:
                    if msg.id == message_id:
                        msg.secure_delete()
                        messages.remove(msg)
                        return
    
    def delete_user_messages(self, user_id: str):
        """Securely delete all messages for a user."""
        with self._lock:
            if user_id in self._pending_messages:
                for msg in self._pending_messages[user_id]:
                    msg.secure_delete()
                del self._pending_messages[user_id]
    
    def cleanup_expired(self) -> int:
        """Delete expired messages with secure wipe."""
        with self._lock:
            now = time.time()
            deleted = 0
            
            for user_id in list(self._pending_messages.keys()):
                new_list = []
                for msg in self._pending_messages[user_id]:
                    if msg.expires_at <= now:
                        msg.secure_delete()
                        deleted += 1
                    else:
                        new_list.append(msg)
                
                if new_list:
                    self._pending_messages[user_id] = new_list
                else:
                    del self._pending_messages[user_id]
            
            gc.collect()
            return deleted
    
    def store_user_keys(self, user_id: str, public_key: bytes,
                        identity_key: bytes, signed_prekey: bytes,
                        prekey_signature: bytes):
        """Store user's public keys."""
        with self._lock:
            # Secure delete old keys if exist
            if user_id in self._user_keys:
                self._user_keys[user_id].secure_delete()
            
            self._user_keys[user_id] = UserKeys(
                user_id=user_id,
                public_key=bytearray(public_key),
                identity_key=bytearray(identity_key),
                signed_prekey=bytearray(signed_prekey),
                prekey_signature=bytearray(prekey_signature),
                updated_at=time.time()
            )
    
    def get_user_keys(self, user_id: str) -> Optional[dict]:
        """Get user's public keys."""
        with self._lock:
            keys = self._user_keys.get(user_id)
            if keys:
                return {
                    'user_id': keys.user_id,
                    'public_key': bytes(keys.public_key),
                    'identity_key': bytes(keys.identity_key),
                    'signed_prekey': bytes(keys.signed_prekey),
                    'prekey_signature': bytes(keys.prekey_signature)
                }
            return None
    
    def delete_user_keys(self, user_id: str):
        """Securely delete user's keys."""
        with self._lock:
            if user_id in self._user_keys:
                self._user_keys[user_id].secure_delete()
                del self._user_keys[user_id]
    
    def panic_wipe_user(self, user_id: str):
        """
        PANIC WIPE - Securely delete ALL data for a user.
        
        Deletes:
        - All messages TO this user
        - All messages FROM this user  
        - User's public keys
        """
        with self._lock:
            # Delete messages TO user
            if user_id in self._pending_messages:
                for msg in self._pending_messages[user_id]:
                    msg.secure_delete()
                del self._pending_messages[user_id]
            
            # Delete messages FROM user (in all recipients)
            for recipient_id in list(self._pending_messages.keys()):
                new_list = []
                for msg in self._pending_messages[recipient_id]:
                    if msg.sender_id == user_id:
                        msg.secure_delete()
                    else:
                        new_list.append(msg)
                
                if new_list:
                    self._pending_messages[recipient_id] = new_list
                else:
                    del self._pending_messages[recipient_id]
            
            # Delete keys
            if user_id in self._user_keys:
                self._user_keys[user_id].secure_delete()
                del self._user_keys[user_id]
            
            # Force garbage collection
            gc.collect()
    
    def wipe_all(self):
        """EMERGENCY: Wipe ALL data from server."""
        with self._lock:
            # Wipe all messages
            for user_id in list(self._pending_messages.keys()):
                for msg in self._pending_messages[user_id]:
                    msg.secure_delete()
            self._pending_messages.clear()
            
            # Wipe all keys
            for user_id in list(self._user_keys.keys()):
                self._user_keys[user_id].secure_delete()
            self._user_keys.clear()
            
            gc.collect()
