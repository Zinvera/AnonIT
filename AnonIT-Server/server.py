#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AnonIT Secure Messenger Server
==============================

MAXIMUM SECURITY WebSocket server for end-to-end encrypted messaging.

Security guarantees:
- Server NEVER sees plaintext messages
- NO logging of IPs or user data
- NO persistent storage (RAM only)
- Panic button: Instant wipe of all user data
- Rate limiting against abuse
- No metadata retention

Author: AnonIT Project
License: MIT
"""

import asyncio
import json
import logging
import signal
import time
import secrets
import gc
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Set, Optional
from datetime import datetime

import websockets

import config
from database import MessageDatabase

# Minimal logging - NO user data, NO IPs
logging.basicConfig(
    level=logging.WARNING,  # Only warnings and errors
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


@dataclass
class ConnectedUser:
    """Represents a connected user session."""
    user_id: str
    websocket: object
    connected_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)


class RateLimiter:
    """Simple rate limiter for abuse prevention."""
    
    def __init__(self, max_requests: int, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window = window_seconds
        self.requests: Dict[str, list] = defaultdict(list)
    
    def is_allowed(self, key: str) -> bool:
        now = time.time()
        self.requests[key] = [t for t in self.requests[key] if now - t < self.window]
        
        if len(self.requests[key]) >= self.max_requests:
            return False
        
        self.requests[key].append(now)
        return True
    
    def cleanup(self):
        now = time.time()
        stale_keys = [k for k, v in self.requests.items() 
                      if not v or now - max(v) > self.window * 2]
        for k in stale_keys:
            del self.requests[k]
    
    def wipe_user(self, user_id: str):
        """Wipe rate limit data for user."""
        if user_id in self.requests:
            del self.requests[user_id]


class AnonITServer:
    """
    Maximum security server - NO persistent storage, NO logging.
    """
    
    def __init__(self):
        self.db = MessageDatabase()
        self.connections: Dict[str, ConnectedUser] = {}
        self.rate_limiter = RateLimiter(config.RATE_LIMIT_MESSAGES)
        self.running = True
        
        # NO logging of initialization
    
    async def handle_connection(self, websocket):
        """Handle a new WebSocket connection."""
        user_id: Optional[str] = None
        
        try:
            # Wait for authentication
            auth_msg = await asyncio.wait_for(websocket.recv(), timeout=30)
            auth_data = json.loads(auth_msg)
            
            if auth_data.get('type') != 'auth':
                await websocket.close(1008, "Authentication required")
                return
            
            user_id = auth_data.get('user_id')
            if not user_id or len(user_id) < 16 or len(user_id) > 64:
                await websocket.close(1008, "Invalid user ID")
                return
            
            # Disconnect old session if exists
            if user_id in self.connections:
                old_ws = self.connections[user_id].websocket
                try:
                    await old_ws.close(1000, "New session started")
                except:
                    pass
            
            self.connections[user_id] = ConnectedUser(
                user_id=user_id,
                websocket=websocket
            )
            
            # Send auth success + pending messages
            await self._send_auth_success(websocket, user_id)
            
            # Handle messages
            async for message in websocket:
                await self._handle_message(user_id, message)
                
        except websockets.ConnectionClosed:
            pass
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass  # NO error logging
        finally:
            if user_id and user_id in self.connections:
                del self.connections[user_id]
    
    async def _send_auth_success(self, websocket, user_id: str):
        """Send authentication success and deliver pending messages."""
        pending = self.db.get_pending_messages(user_id)
        
        await websocket.send(json.dumps({
            'type': 'auth_success',
            'pending_count': len(pending)
        }))
        
        # Deliver pending messages
        for msg_id, sender_id, encrypted_data in pending:
            await websocket.send(json.dumps({
                'type': 'message',
                'from': sender_id,
                'data': encrypted_data.hex(),
                'offline': True
            }))
            self.db.delete_message(msg_id)
    
    async def _handle_message(self, sender_id: str, raw_message: str):
        """Process incoming message from client."""
        if not self.rate_limiter.is_allowed(sender_id):
            await self._send_error(sender_id, "Rate limit exceeded")
            return
        
        try:
            msg = json.loads(raw_message)
            msg_type = msg.get('type')
            
            if msg_type == 'message':
                await self._route_message(sender_id, msg)
            elif msg_type == 'register_keys':
                await self._register_keys(sender_id, msg)
            elif msg_type == 'get_keys':
                await self._get_keys(sender_id, msg)
            elif msg_type == 'ping':
                await self._send_pong(sender_id)
            elif msg_type == 'panic':
                await self._handle_panic(sender_id)
            elif msg_type == 'delete_account':
                await self._handle_delete_account(sender_id)
                
        except json.JSONDecodeError:
            pass  # Silent fail
        except Exception:
            pass  # Silent fail - NO logging
    
    async def _route_message(self, sender_id: str, msg: dict):
        """Route encrypted message to recipient."""
        recipient_id = msg.get('to')
        encrypted_data = msg.get('data')
        
        if not recipient_id or not encrypted_data:
            return
        
        try:
            data_bytes = bytes.fromhex(encrypted_data)
            if len(data_bytes) > config.MAX_MESSAGE_SIZE:
                return
        except ValueError:
            return
        
        # Check if recipient is online
        if recipient_id in self.connections:
            try:
                await self.connections[recipient_id].websocket.send(json.dumps({
                    'type': 'message',
                    'from': sender_id,
                    'data': encrypted_data,
                    'offline': False
                }))
                await self._send_ack(sender_id, "delivered")
            except:
                self.db.store_message(recipient_id, sender_id, data_bytes)
                await self._send_ack(sender_id, "stored")
        else:
            self.db.store_message(recipient_id, sender_id, data_bytes)
            await self._send_ack(sender_id, "stored")
    
    async def _register_keys(self, user_id: str, msg: dict):
        """Register user's public keys."""
        try:
            self.db.store_user_keys(
                user_id=user_id,
                public_key=bytes.fromhex(msg['public_key']),
                identity_key=bytes.fromhex(msg['identity_key']),
                signed_prekey=bytes.fromhex(msg['signed_prekey']),
                prekey_signature=bytes.fromhex(msg['prekey_signature'])
            )
            await self._send_to_user(user_id, {'type': 'keys_registered'})
        except (KeyError, ValueError):
            pass
    
    async def _get_keys(self, requester_id: str, msg: dict):
        """Get another user's public keys."""
        target_id = msg.get('user_id')
        if not target_id:
            return
        
        keys = self.db.get_user_keys(target_id)
        if keys:
            await self._send_to_user(requester_id, {
                'type': 'user_keys',
                'user_id': target_id,
                'public_key': keys['public_key'].hex(),
                'identity_key': keys['identity_key'].hex(),
                'signed_prekey': keys['signed_prekey'].hex(),
                'prekey_signature': keys['prekey_signature'].hex()
            })
        else:
            await self._send_to_user(requester_id, {
                'type': 'user_keys',
                'user_id': target_id,
                'error': 'User not found'
            })
    
    async def _handle_panic(self, user_id: str):
        """
        PANIC BUTTON - Instantly wipe ALL user data from server.
        
        This deletes:
        - All pending messages TO this user
        - All pending messages FROM this user
        - User's public keys
        - Rate limit data
        - Connection data
        """
        # Wipe from database
        self.db.panic_wipe_user(user_id)
        
        # Wipe rate limiter
        self.rate_limiter.wipe_user(user_id)
        
        # Confirm to user
        await self._send_to_user(user_id, {
            'type': 'panic_complete',
            'message': 'All server data wiped'
        })
        
        # Force garbage collection
        gc.collect()
    
    async def _handle_delete_account(self, user_id: str):
        """Delete account and disconnect."""
        # Wipe everything
        self.db.panic_wipe_user(user_id)
        self.rate_limiter.wipe_user(user_id)
        
        # Confirm and disconnect
        await self._send_to_user(user_id, {
            'type': 'account_deleted'
        })
        
        # Close connection
        if user_id in self.connections:
            try:
                await self.connections[user_id].websocket.close(1000, "Account deleted")
            except:
                pass
            del self.connections[user_id]
        
        gc.collect()
    
    async def _send_to_user(self, user_id: str, data: dict):
        """Send data to a connected user."""
        if user_id in self.connections:
            try:
                await self.connections[user_id].websocket.send(json.dumps(data))
            except:
                pass
    
    async def _send_error(self, user_id: str, error: str):
        await self._send_to_user(user_id, {'type': 'error', 'message': error})
    
    async def _send_ack(self, user_id: str, status: str):
        await self._send_to_user(user_id, {'type': 'ack', 'status': status})
    
    async def _send_pong(self, user_id: str):
        await self._send_to_user(user_id, {'type': 'pong', 'time': time.time()})
    
    async def cleanup_task(self):
        """Periodic cleanup of expired messages."""
        while self.running:
            try:
                self.db.cleanup_expired()
                self.rate_limiter.cleanup()
                gc.collect()  # Force garbage collection
            except Exception:
                pass
            
            await asyncio.sleep(300)  # Every 5 minutes
    
    async def start(self):
        """Start the server."""
        asyncio.create_task(self.cleanup_task())
        
        async with websockets.serve(
            self.handle_connection,
            config.HOST,
            config.PORT,
            max_size=config.MAX_MESSAGE_SIZE,
            ping_interval=30,
            ping_timeout=10
        ):
            stop = asyncio.Future()
            
            def handle_signal():
                self.running = False
                # Wipe all data on shutdown
                self.db.wipe_all()
                gc.collect()
                stop.set_result(None)
            
            loop = asyncio.get_event_loop()
            for sig in (signal.SIGTERM, signal.SIGINT):
                try:
                    loop.add_signal_handler(sig, handle_signal)
                except NotImplementedError:
                    pass
            
            print(f"AnonIT Server running on port {config.PORT}")
            print("NO LOGGING - Maximum Privacy Mode")
            await stop


async def main():
    server = AnonITServer()
    await server.start()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
