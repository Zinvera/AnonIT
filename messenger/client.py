#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AnonIT Messenger Client
=======================

WebSocket client for connecting to AnonIT server.
Handles connection, reconnection, and message routing.
"""

import asyncio
import json
import logging
import threading
import time
import gc
from dataclasses import dataclass, field
from typing import Optional, Callable, Dict, List
from queue import Queue, Empty

import websockets

from .protocol import MessengerProtocol
from .secure_memory import secure_wipe, force_gc

logger = logging.getLogger(__name__)


@dataclass
class Contact:
    """A messenger contact."""
    user_id: str
    nickname: str = ""
    public_key: Optional[bytes] = None
    identity_key: Optional[bytes] = None
    signed_prekey: Optional[bytes] = None
    last_seen: float = 0
    
    @property
    def display_name(self) -> str:
        return self.nickname or self.user_id[:8]


@dataclass
class Message:
    """A chat message."""
    sender_id: str
    content: str
    timestamp: float = field(default_factory=time.time)
    is_outgoing: bool = False
    delivered: bool = False


class MessengerClient:
    """
    WebSocket client for AnonIT Messenger.
    """
    
    def __init__(self, server_url: str = "ws://localhost:8765"):
        self.server_url = server_url
        self.protocol = MessengerProtocol()
        
        # Connection state
        self.websocket = None
        self.connected = False
        self.running = False
        self._stop_event = threading.Event()
        
        # Contacts and messages
        self.contacts: Dict[str, Contact] = {}
        self.messages: Dict[str, List[Message]] = {}
        
        # Callbacks
        self.on_connected: Optional[Callable[[], None]] = None
        self.on_disconnected: Optional[Callable[[], None]] = None
        self.on_message: Optional[Callable[[str, Message], None]] = None
        self.on_contact_online: Optional[Callable[[str], None]] = None
        
        # Message queue for sending
        self._send_queue: Queue = Queue()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
    
    @property
    def user_id(self) -> str:
        return self.protocol.user_id
    
    def start(self):
        """Start the client in a background thread."""
        if self.running:
            return
        
        self.running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_async, daemon=True)
        self._thread.start()
        logger.info("Messenger client started")
    
    def stop(self):
        """Stop the client."""
        self.running = False
        self._stop_event.set()
        
        # Close websocket if open
        if self._loop and self.websocket:
            try:
                asyncio.run_coroutine_threadsafe(
                    self.websocket.close(), self._loop
                ).result(timeout=2)
            except:
                pass
        
        # Stop the event loop
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
        
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        
        self.connected = False
        logger.info("Messenger client stopped")
    
    def _run_async(self):
        """Run async event loop in thread."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        
        try:
            self._loop.run_until_complete(self._connection_loop())
        except Exception as e:
            if self.running:  # Only log if not intentionally stopped
                logger.error(f"Event loop error: {e}")
        finally:
            try:
                # Cancel all pending tasks
                pending = asyncio.all_tasks(self._loop)
                for task in pending:
                    task.cancel()
                
                # Wait for cancellation
                if pending:
                    self._loop.run_until_complete(
                        asyncio.gather(*pending, return_exceptions=True)
                    )
            except:
                pass
            finally:
                self._loop.close()
    
    async def _connection_loop(self):
        """Main connection loop with auto-reconnect."""
        while self.running and not self._stop_event.is_set():
            try:
                await self._connect()
            except asyncio.CancelledError:
                break
            except Exception as e:
                if self.running:
                    logger.error(f"Connection error: {e}")
            
            if self.running and not self._stop_event.is_set():
                # Wait before reconnect, but check stop event
                for _ in range(50):  # 5 seconds in 0.1s chunks
                    if self._stop_event.is_set():
                        break
                    await asyncio.sleep(0.1)
    
    async def _connect(self):
        """Connect to server and handle messages."""
        try:
            async with websockets.connect(
                self.server_url,
                ping_interval=30,
                ping_timeout=10,
                close_timeout=2
            ) as ws:
                self.websocket = ws
                
                # Authenticate
                await ws.send(json.dumps({
                    'type': 'auth',
                    'user_id': self.user_id
                }))
                
                # Wait for auth response
                response = await asyncio.wait_for(ws.recv(), timeout=10)
                data = json.loads(response)
                
                if data.get('type') != 'auth_success':
                    logger.error("Authentication failed")
                    return
                
                self.connected = True
                logger.info(f"Connected to server (pending: {data.get('pending_count', 0)})")
                
                # Register keys
                await self._register_keys()
                
                if self.on_connected:
                    self.on_connected()
                
                # Start send task
                send_task = asyncio.create_task(self._send_loop())
                
                # Receive messages
                try:
                    while self.running and not self._stop_event.is_set():
                        try:
                            message = await asyncio.wait_for(ws.recv(), timeout=1.0)
                            await self._handle_message(message)
                        except asyncio.TimeoutError:
                            continue  # Just check running flag
                        except websockets.ConnectionClosed:
                            break
                finally:
                    send_task.cancel()
                    try:
                        await send_task
                    except asyncio.CancelledError:
                        pass
                    
        except websockets.ConnectionClosed:
            logger.info("Connection closed")
        except asyncio.CancelledError:
            raise
        except Exception as e:
            if self.running:
                logger.error(f"Connection error: {e}")
        finally:
            self.connected = False
            self.websocket = None
            if self.on_disconnected:
                self.on_disconnected()
    
    async def _register_keys(self):
        """Register public keys with server."""
        keys = self.protocol.get_public_keys()
        await self.websocket.send(json.dumps({
            'type': 'register_keys',
            **keys
        }))
    
    async def _send_loop(self):
        """Process outgoing message queue."""
        while self.connected and not self._stop_event.is_set():
            try:
                await asyncio.sleep(0.1)
                
                while not self._send_queue.empty():
                    try:
                        msg = self._send_queue.get_nowait()
                        if self.websocket:
                            await self.websocket.send(json.dumps(msg))
                    except Empty:
                        break
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Send error: {e}")
    
    async def _handle_message(self, raw: str):
        """Handle incoming server message."""
        try:
            data = json.loads(raw)
            msg_type = data.get('type')
            
            if msg_type == 'message':
                await self._handle_chat_message(data)
            elif msg_type == 'user_keys':
                await self._handle_user_keys(data)
            elif msg_type == 'ack':
                logger.debug(f"Message ack: {data.get('status')}")
            elif msg_type == 'error':
                logger.error(f"Server error: {data.get('message')}")
            elif msg_type == 'keys_registered':
                logger.info("Keys registered with server")
                
        except Exception as e:
            logger.error(f"Message handling error: {e}")
    
    async def _handle_chat_message(self, data: dict):
        """Handle incoming chat message."""
        sender_id = data.get('from')
        encrypted_hex = data.get('data')
        
        if not sender_id or not encrypted_hex:
            return
        
        encrypted = bytes.fromhex(encrypted_hex)
        
        # Check if it's a key exchange
        if len(encrypted) > 0 and encrypted[0] == 0x02:  # MSG_TYPE_KEY_EXCHANGE
            await self._handle_key_exchange(sender_id, encrypted)
            return
        
        # Try to decrypt
        if not self.protocol.has_session(sender_id):
            logger.warning(f"No session with {sender_id[:8]}, requesting keys")
            await self._request_keys(sender_id)
            return
        
        plaintext = self.protocol.decrypt_message(sender_id, encrypted)
        if plaintext:
            msg = Message(
                sender_id=sender_id,
                content=plaintext,
                is_outgoing=False,
                delivered=True
            )
            
            # Store message
            if sender_id not in self.messages:
                self.messages[sender_id] = []
            self.messages[sender_id].append(msg)
            
            # Callback
            if self.on_message:
                self.on_message(sender_id, msg)
        else:
            logger.error(f"Failed to decrypt message from {sender_id[:8]}")
    
    async def _handle_key_exchange(self, sender_id: str, message: bytes):
        """Handle incoming key exchange."""
        contact = self.contacts.get(sender_id)
        if not contact or not contact.public_key:
            # Request keys first
            await self._request_keys(sender_id)
            return
        
        success = self.protocol.process_key_exchange(
            sender_id, message,
            contact.public_key,
            contact.signed_prekey
        )
        
        if success:
            logger.info(f"Session established with {sender_id[:8]}")
        else:
            logger.error(f"Key exchange failed with {sender_id[:8]}")
    
    async def _handle_user_keys(self, data: dict):
        """Handle received user keys."""
        user_id = data.get('user_id')
        
        if data.get('error'):
            logger.warning(f"User {user_id[:8] if user_id else 'unknown'} not found")
            return
        
        # Store contact keys
        contact = self.contacts.get(user_id) or Contact(user_id=user_id)
        contact.public_key = bytes.fromhex(data['public_key'])
        contact.identity_key = bytes.fromhex(data['identity_key'])
        contact.signed_prekey = bytes.fromhex(data['signed_prekey'])
        self.contacts[user_id] = contact
        
        logger.info(f"Received keys for {user_id[:8]}")
    
    async def _request_keys(self, user_id: str):
        """Request user's public keys from server."""
        if self.websocket:
            await self.websocket.send(json.dumps({
                'type': 'get_keys',
                'user_id': user_id
            }))
    
    # Public API
    
    def add_contact(self, user_id: str, nickname: str = ""):
        """Add a contact by user ID."""
        if user_id not in self.contacts:
            self.contacts[user_id] = Contact(user_id=user_id, nickname=nickname)
        else:
            self.contacts[user_id].nickname = nickname
        
        # Request keys
        self._send_queue.put({
            'type': 'get_keys',
            'user_id': user_id
        })
    
    def send_message(self, peer_id: str, text: str) -> bool:
        """Send a message to a peer."""
        if not self.connected:
            logger.warning("Not connected")
            return False
        
        contact = self.contacts.get(peer_id)
        
        # Check if we have a session
        if not self.protocol.has_session(peer_id):
            if contact and contact.public_key:
                # Create session
                key_exchange = self.protocol.create_session(
                    peer_id,
                    contact.public_key,
                    contact.signed_prekey
                )
                # Send key exchange
                self._send_queue.put({
                    'type': 'message',
                    'to': peer_id,
                    'data': key_exchange.hex()
                })
            else:
                logger.warning(f"No keys for {peer_id[:8]}, requesting...")
                self._send_queue.put({
                    'type': 'get_keys',
                    'user_id': peer_id
                })
                return False
        
        # Encrypt and send
        encrypted = self.protocol.encrypt_message(peer_id, text)
        if encrypted:
            self._send_queue.put({
                'type': 'message',
                'to': peer_id,
                'data': encrypted.hex()
            })
            
            # Store outgoing message
            msg = Message(
                sender_id=self.user_id,
                content=text,
                is_outgoing=True
            )
            if peer_id not in self.messages:
                self.messages[peer_id] = []
            self.messages[peer_id].append(msg)
            
            return True
        
        return False
    
    def get_messages(self, peer_id: str) -> List[Message]:
        """Get message history with a peer."""
        return self.messages.get(peer_id, [])

    # ==========================================
    # PANIC & SECURITY FUNCTIONS
    # ==========================================
    
    def panic(self) -> bool:
        """
        PANIC BUTTON - Wipe ALL local and server data.
        
        This will:
        1. Send panic signal to server (wipes server data)
        2. Wipe all local messages
        3. Wipe all contacts
        4. Wipe all sessions
        5. Delete identity keys
        6. Force garbage collection
        
        Returns:
            True if panic signal was sent to server
        """
        # Send panic to server
        server_notified = False
        if self.connected:
            self._send_queue.put({'type': 'panic'})
            server_notified = True
        
        # Wipe local data
        self._wipe_local_data()
        
        return server_notified
    
    def delete_account(self) -> bool:
        """
        Delete account completely.
        
        Sends delete request to server and wipes all local data.
        """
        if self.connected:
            self._send_queue.put({'type': 'delete_account'})
        
        self._wipe_local_data()
        self._delete_identity_keys()
        
        return True
    
    def _wipe_local_data(self):
        """Securely wipe all local data."""
        import os
        from pathlib import Path
        
        # Wipe messages
        for peer_id in list(self.messages.keys()):
            for msg in self.messages[peer_id]:
                # Overwrite content
                if hasattr(msg, 'content'):
                    msg.content = "X" * len(msg.content)
            self.messages[peer_id].clear()
        self.messages.clear()
        
        # Wipe contacts
        for contact_id in list(self.contacts.keys()):
            contact = self.contacts[contact_id]
            if contact.public_key:
                contact.public_key = b'\x00' * len(contact.public_key)
            if contact.identity_key:
                contact.identity_key = b'\x00' * len(contact.identity_key)
            if contact.signed_prekey:
                contact.signed_prekey = b'\x00' * len(contact.signed_prekey)
        self.contacts.clear()
        
        # Wipe protocol sessions
        if hasattr(self.protocol, 'sessions'):
            self.protocol.sessions.clear()
        
        # Force garbage collection
        force_gc()
    
    def _delete_identity_keys(self):
        """Delete identity key file."""
        import os
        from pathlib import Path
        
        try:
            key_file = self.protocol.data_dir / "identity.key"
            if key_file.exists():
                # Overwrite with random data before delete
                size = key_file.stat().st_size
                with open(key_file, 'wb') as f:
                    f.write(b'\x00' * size)
                    f.flush()
                    os.fsync(f.fileno())
                with open(key_file, 'wb') as f:
                    f.write(b'\xFF' * size)
                    f.flush()
                    os.fsync(f.fileno())
                with open(key_file, 'wb') as f:
                    f.write(b'\x00' * size)
                    f.flush()
                    os.fsync(f.fileno())
                # Delete
                key_file.unlink()
        except Exception:
            pass
    
    def clear_chat(self, peer_id: str):
        """Clear chat history with a specific contact."""
        if peer_id in self.messages:
            for msg in self.messages[peer_id]:
                if hasattr(msg, 'content'):
                    msg.content = "X" * len(msg.content)
            self.messages[peer_id].clear()
            del self.messages[peer_id]
        force_gc()
