#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AnonIT Messenger Protocol
=========================

End-to-end encryption protocol using X25519 key exchange and AES-256-GCM.
Implements a simplified Signal-like protocol for forward secrecy.
"""

import hashlib
import hmac
import json
import secrets
import struct
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Tuple
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# Message types
MSG_TYPE_TEXT = 0x01
MSG_TYPE_KEY_EXCHANGE = 0x02
MSG_TYPE_ACK = 0x03


@dataclass
class KeyPair:
    """X25519 key pair for key exchange."""
    private_key: X25519PrivateKey
    public_key: X25519PublicKey
    
    @classmethod
    def generate(cls) -> 'KeyPair':
        private = X25519PrivateKey.generate()
        return cls(private_key=private, public_key=private.public_key())
    
    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def private_bytes(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )


@dataclass
class Session:
    """Encrypted session with another user."""
    peer_id: str
    shared_secret: bytes
    send_chain_key: bytes
    recv_chain_key: bytes
    send_counter: int = 0
    recv_counter: int = 0
    created_at: float = field(default_factory=time.time)


class MessengerProtocol:
    """
    End-to-end encryption protocol for AnonIT Messenger.
    
    Key features:
    - X25519 Diffie-Hellman key exchange
    - AES-256-GCM authenticated encryption
    - Key ratcheting for forward secrecy
    - No plaintext ever leaves this module
    """
    
    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or Path.home() / ".anonit"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Identity keys (long-term)
        self.identity_key: Optional[KeyPair] = None
        self.signed_prekey: Optional[KeyPair] = None
        
        # Active sessions
        self.sessions: Dict[str, Session] = {}
        
        # User ID (derived from identity key)
        self.user_id: Optional[str] = None
        
        self._load_or_generate_keys()
    
    def _load_or_generate_keys(self):
        """Load existing keys or generate new ones."""
        key_file = self.data_dir / "identity.key"
        
        if key_file.exists():
            try:
                data = key_file.read_bytes()
                # Format: identity_private(32) + prekey_private(32)
                if len(data) == 64:
                    id_private = X25519PrivateKey.from_private_bytes(data[:32])
                    pk_private = X25519PrivateKey.from_private_bytes(data[32:])
                    
                    self.identity_key = KeyPair(id_private, id_private.public_key())
                    self.signed_prekey = KeyPair(pk_private, pk_private.public_key())
                    self._derive_user_id()
                    return
            except Exception:
                pass
        
        # Generate new keys
        self.identity_key = KeyPair.generate()
        self.signed_prekey = KeyPair.generate()
        self._derive_user_id()
        
        # Save keys
        key_data = self.identity_key.private_bytes() + self.signed_prekey.private_bytes()
        key_file.write_bytes(key_data)
    
    def _derive_user_id(self):
        """Derive user ID from identity public key."""
        pub_bytes = self.identity_key.public_bytes()
        self.user_id = hashlib.sha256(pub_bytes).hexdigest()[:32]
    
    def get_public_keys(self) -> dict:
        """Get public keys for registration with server."""
        # Sign the prekey with identity key (simplified - just HMAC)
        prekey_bytes = self.signed_prekey.public_bytes()
        signature = hmac.new(
            self.identity_key.private_bytes(),
            prekey_bytes,
            hashlib.sha256
        ).digest()
        
        return {
            'public_key': self.identity_key.public_bytes().hex(),
            'identity_key': self.identity_key.public_bytes().hex(),
            'signed_prekey': self.signed_prekey.public_bytes().hex(),
            'prekey_signature': signature.hex()
        }
    
    def create_session(self, peer_id: str, peer_public_key: bytes,
                       peer_prekey: bytes) -> bytes:
        """
        Create a new session with a peer using X3DH-like key agreement.
        
        Returns:
            Initial key exchange message to send to peer
        """
        # Generate ephemeral key
        ephemeral = KeyPair.generate()
        
        # Load peer's public key
        peer_identity = X25519PublicKey.from_public_bytes(peer_public_key)
        peer_signed_prekey = X25519PublicKey.from_public_bytes(peer_prekey)
        
        # X3DH key agreement (simplified)
        # DH1 = DH(IK_A, SPK_B)
        dh1 = self.identity_key.private_key.exchange(peer_signed_prekey)
        # DH2 = DH(EK_A, IK_B)
        dh2 = ephemeral.private_key.exchange(peer_identity)
        # DH3 = DH(EK_A, SPK_B)
        dh3 = ephemeral.private_key.exchange(peer_signed_prekey)
        
        # Combine DH outputs
        shared_secret = self._kdf(dh1 + dh2 + dh3, b"AnonIT-Session")
        
        # Derive chain keys
        send_chain = self._kdf(shared_secret, b"send-chain")
        recv_chain = self._kdf(shared_secret, b"recv-chain")
        
        # Create session
        self.sessions[peer_id] = Session(
            peer_id=peer_id,
            shared_secret=shared_secret,
            send_chain_key=send_chain,
            recv_chain_key=recv_chain
        )
        
        # Create key exchange message
        return self._create_key_exchange_message(ephemeral.public_bytes())
    
    def process_key_exchange(self, peer_id: str, message: bytes,
                             peer_public_key: bytes, peer_prekey: bytes) -> bool:
        """Process incoming key exchange message."""
        try:
            # Parse message
            if len(message) < 33:
                return False
            
            msg_type = message[0]
            if msg_type != MSG_TYPE_KEY_EXCHANGE:
                return False
            
            ephemeral_pub = message[1:33]
            ephemeral_key = X25519PublicKey.from_public_bytes(ephemeral_pub)
            
            # Load peer keys
            peer_identity = X25519PublicKey.from_public_bytes(peer_public_key)
            
            # Reverse X3DH
            dh1 = self.signed_prekey.private_key.exchange(peer_identity)
            dh2 = self.identity_key.private_key.exchange(ephemeral_key)
            dh3 = self.signed_prekey.private_key.exchange(ephemeral_key)
            
            shared_secret = self._kdf(dh1 + dh2 + dh3, b"AnonIT-Session")
            
            # Note: chain keys are reversed for receiver
            recv_chain = self._kdf(shared_secret, b"send-chain")
            send_chain = self._kdf(shared_secret, b"recv-chain")
            
            self.sessions[peer_id] = Session(
                peer_id=peer_id,
                shared_secret=shared_secret,
                send_chain_key=send_chain,
                recv_chain_key=recv_chain
            )
            
            return True
        except Exception:
            return False
    
    def _create_key_exchange_message(self, ephemeral_pub: bytes) -> bytes:
        """Create key exchange message."""
        return bytes([MSG_TYPE_KEY_EXCHANGE]) + ephemeral_pub
    
    def encrypt_message(self, peer_id: str, plaintext: str) -> Optional[bytes]:
        """
        Encrypt a message for a peer.
        
        Returns:
            Encrypted message bytes, or None if no session exists
        """
        session = self.sessions.get(peer_id)
        if not session:
            return None
        
        # Ratchet send chain
        message_key, session.send_chain_key = self._ratchet(session.send_chain_key)
        
        # Encrypt with AES-GCM
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(message_key)
        
        # Message format: type(1) + counter(4) + nonce(12) + ciphertext
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
        
        message = (
            bytes([MSG_TYPE_TEXT]) +
            struct.pack('>I', session.send_counter) +
            nonce +
            ciphertext
        )
        
        session.send_counter += 1
        return message
    
    def decrypt_message(self, peer_id: str, encrypted: bytes) -> Optional[str]:
        """
        Decrypt a message from a peer.
        
        Returns:
            Decrypted plaintext, or None if decryption fails
        """
        session = self.sessions.get(peer_id)
        if not session:
            return None
        
        try:
            if len(encrypted) < 17:
                return None
            
            msg_type = encrypted[0]
            if msg_type != MSG_TYPE_TEXT:
                return None
            
            counter = struct.unpack('>I', encrypted[1:5])[0]
            nonce = encrypted[5:17]
            ciphertext = encrypted[17:]
            
            # Ratchet to correct position
            # (simplified - in production, handle out-of-order messages)
            while session.recv_counter <= counter:
                message_key, session.recv_chain_key = self._ratchet(session.recv_chain_key)
                session.recv_counter += 1
            
            # Decrypt
            aesgcm = AESGCM(message_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            return plaintext.decode('utf-8')
        except Exception:
            return None
    
    def _kdf(self, input_key: bytes, info: bytes) -> bytes:
        """Derive key using HKDF."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
            backend=default_backend()
        )
        return hkdf.derive(input_key)
    
    def _ratchet(self, chain_key: bytes) -> Tuple[bytes, bytes]:
        """Ratchet chain key to get message key and new chain key."""
        message_key = hmac.new(chain_key, b'\x01', hashlib.sha256).digest()
        new_chain_key = hmac.new(chain_key, b'\x02', hashlib.sha256).digest()
        return message_key, new_chain_key
    
    def has_session(self, peer_id: str) -> bool:
        """Check if session exists with peer."""
        return peer_id in self.sessions
    
    def delete_session(self, peer_id: str):
        """Delete session with peer."""
        if peer_id in self.sessions:
            del self.sessions[peer_id]
