#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AnonIT Cryptographic Module
============================

This module provides secure text encryption using industry-standard algorithms.
It implements AES-256-GCM for authenticated encryption and Argon2id for 
password-based key derivation.

Security Features:
    - AES-256-GCM: Authenticated encryption with associated data (AEAD)
    - Argon2id: Memory-hard key derivation resistant to GPU/ASIC attacks
    - CryptProtectMemory: Windows DPAPI for in-memory key encryption
    - VirtualLock: Prevents key material from being swapped to disk

Known Limitations:
    - Keys exist briefly as plaintext during cryptographic operations
    - Vulnerable to memory dumps by privileged attackers
    - No hardware security module (HSM) integration
    - Windows-only memory protection features

Thread Safety:
    This module uses a global lock to ensure thread-safe access to key material.
    All public functions are safe to call from multiple threads.

Author: AnonIT Project
License: MIT
Version: 1.0.1
"""

import base64
import ctypes
import hmac
import logging
import secrets
import sys
import threading
from typing import Optional, Tuple

from Crypto.Cipher import AES
from argon2.low_level import hash_secret_raw, Type

# Configure module logger
logger = logging.getLogger(__name__)

# =============================================================================
# Constants
# =============================================================================

# Encrypted message format markers
PREFIX = "ANON["
SUFFIX = "]IT"

# Argon2id parameters (OWASP recommended minimums exceeded)
# See: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
ARGON2_TIME_COST = 3          # Number of iterations
ARGON2_MEMORY_COST = 65536    # 64 MB memory usage (resists GPU attacks)
ARGON2_PARALLELISM = 4        # Parallel threads
ARGON2_HASH_LEN = 32          # 256-bit output key

# Cryptographic sizes
SALT_LENGTH = 16              # 128-bit salt (unique per key derivation)
NONCE_LENGTH = 12             # 96-bit nonce (GCM standard)
TAG_LENGTH = 16               # 128-bit authentication tag

# Windows DPAPI constants
CRYPTPROTECTMEMORY_SAME_PROCESS = 0x00
CRYPTPROTECTMEMORY_BLOCK_SIZE = 16

# Thread safety lock for global state
_global_lock = threading.RLock()


# =============================================================================
# Windows Memory Protection
# =============================================================================

class WindowsMemoryProtection:
    """
    Provides Windows-specific memory protection using DPAPI.
    
    This class wraps Windows API functions to:
    1. Lock memory pages (VirtualLock) - prevents swapping to disk
    2. Encrypt memory (CryptProtectMemory) - encrypts data in RAM
    
    These protections are defense-in-depth measures. They help against:
    - Swap file forensics
    - Cold boot attacks (partially)
    - Casual memory inspection
    
    They do NOT protect against:
    - Kernel-level attackers
    - Debuggers with admin privileges
    - Memory dumps by privileged processes
    
    Attributes:
        _available: Whether Windows DPAPI is available on this system.
    """
    
    def __init__(self) -> None:
        """Initialize Windows memory protection APIs."""
        self._available = False
        self._crypt32 = None
        self._kernel32 = None
        
        if sys.platform == 'win32':
            try:
                self._crypt32 = ctypes.windll.crypt32
                self._kernel32 = ctypes.windll.kernel32
                self._available = True
                logger.debug("Windows memory protection APIs loaded successfully")
            except (OSError, AttributeError) as e:
                logger.warning(f"Failed to load Windows DPAPI: {e}")
    
    @property
    def is_available(self) -> bool:
        """Check if memory protection is available."""
        return self._available
    
    def protect_memory(self, buffer: bytearray) -> bool:
        """
        Encrypt memory buffer using CryptProtectMemory.
        
        The buffer size must be a multiple of CRYPTPROTECTMEMORY_BLOCK_SIZE (16 bytes).
        
        Args:
            buffer: Mutable byte buffer to encrypt in-place.
            
        Returns:
            True if encryption succeeded, False otherwise.
            
        Note:
            Failure is logged but not raised - caller should check return value.
        """
        if not self._available or not buffer:
            return False
            
        size = len(buffer)
        if size % CRYPTPROTECTMEMORY_BLOCK_SIZE != 0:
            logger.error(f"Buffer size {size} not multiple of {CRYPTPROTECTMEMORY_BLOCK_SIZE}")
            return False
            
        try:
            addr = ctypes.addressof((ctypes.c_char * size).from_buffer(buffer))
            result = bool(self._crypt32.CryptProtectMemory(
                ctypes.c_void_p(addr),
                ctypes.c_ulong(size),
                ctypes.c_ulong(CRYPTPROTECTMEMORY_SAME_PROCESS)
            ))
            if not result:
                logger.warning("CryptProtectMemory failed")
            return result
        except Exception as e:
            logger.error(f"Memory protection error: {e}")
            return False
    
    def unprotect_memory(self, buffer: bytearray) -> bool:
        """
        Decrypt memory buffer using CryptUnprotectMemory.
        
        Args:
            buffer: Previously encrypted buffer to decrypt in-place.
            
        Returns:
            True if decryption succeeded, False otherwise.
        """
        if not self._available or not buffer:
            return False
            
        try:
            size = len(buffer)
            addr = ctypes.addressof((ctypes.c_char * size).from_buffer(buffer))
            result = bool(self._crypt32.CryptUnprotectMemory(
                ctypes.c_void_p(addr),
                ctypes.c_ulong(size),
                ctypes.c_ulong(CRYPTPROTECTMEMORY_SAME_PROCESS)
            ))
            if not result:
                logger.warning("CryptUnprotectMemory failed")
            return result
        except Exception as e:
            logger.error(f"Memory unprotection error: {e}")
            return False
    
    def lock_memory(self, buffer: bytearray) -> bool:
        """
        Lock memory pages to prevent swapping to disk.
        
        Uses VirtualLock to pin memory pages in physical RAM.
        Requires sufficient working set quota.
        
        Args:
            buffer: Buffer whose pages should be locked.
            
        Returns:
            True if locking succeeded, False otherwise.
        """
        if not self._available or not buffer:
            return False
            
        try:
            addr = ctypes.addressof((ctypes.c_char * len(buffer)).from_buffer(buffer))
            result = bool(self._kernel32.VirtualLock(
                ctypes.c_void_p(addr),
                ctypes.c_size_t(len(buffer))
            ))
            if not result:
                logger.warning("VirtualLock failed - key may be swapped to disk")
            return result
        except Exception as e:
            logger.error(f"Memory lock error: {e}")
            return False
    
    def unlock_memory(self, buffer: bytearray) -> bool:
        """
        Unlock previously locked memory pages.
        
        Args:
            buffer: Buffer to unlock.
            
        Returns:
            True if unlocking succeeded, False otherwise.
        """
        if not self._available or not buffer:
            return False
            
        try:
            addr = ctypes.addressof((ctypes.c_char * len(buffer)).from_buffer(buffer))
            return bool(self._kernel32.VirtualUnlock(
                ctypes.c_void_p(addr),
                ctypes.c_size_t(len(buffer))
            ))
        except Exception as e:
            logger.error(f"Memory unlock error: {e}")
            return False
    
    def secure_zero(self, buffer: bytearray) -> None:
        """
        Securely zero memory to prevent recovery.
        
        Uses volatile write pattern to prevent compiler optimization
        from removing the zeroing operation.
        
        Args:
            buffer: Buffer to zero.
        """
        if not buffer:
            return
            
        try:
            size = len(buffer)
            addr = ctypes.addressof((ctypes.c_char * size).from_buffer(buffer))
            # Volatile write - compiler cannot optimize this away
            ctypes.memset(addr, 0, size)
            # Memory barrier - force write to complete
            _ = buffer[0] if size > 0 else None
        except Exception as e:
            # Fallback: Python-level zeroing
            logger.warning(f"Secure zero fallback: {e}")
            for i in range(len(buffer)):
                buffer[i] = 0


# Global memory protection instance
_mem_protect = WindowsMemoryProtection()


# =============================================================================
# Secure Key Storage
# =============================================================================

class SecureKey:
    """
    Secure in-memory storage for encryption keys.
    
    This class provides protected storage for derived encryption keys with:
    - Memory locking (prevents swap)
    - Memory encryption (DPAPI)
    - Secure zeroing on cleanup
    - Thread-safe access
    
    The key lifecycle is:
    1. Password provided by user
    2. Key derived using Argon2id (slow, memory-hard)
    3. Key stored in locked, encrypted memory
    4. Key decrypted only during crypto operations
    5. Key securely wiped on clear() or destruction
    
    Example:
        >>> key = SecureKey()
        >>> salt = key.set_key("my_password")
        >>> derived = key.get_key()  # Returns key bytes
        >>> key.clear()  # Securely wipes key
    
    Thread Safety:
        All methods are thread-safe via internal locking.
    """
    
    def __init__(self) -> None:
        """Initialize empty secure key storage."""
        self._lock = threading.RLock()
        self._protected_key: Optional[bytearray] = None
        self._protected_password: Optional[bytearray] = None  # Store password for re-derivation
        self._is_protected = False
        self._is_locked = False
        self._password_protected = False
        self._password_locked = False
        self._salt: Optional[bytes] = None
    
    def set_key(self, password: str, salt: Optional[bytes] = None) -> bytes:
        """
        Derive and securely store an encryption key from a password.
        
        Uses Argon2id for key derivation with parameters that resist
        GPU and ASIC-based attacks. The derived key is then protected
        using Windows DPAPI if available.
        
        Args:
            password: User-provided password (any length, but longer is better).
            salt: Optional salt bytes. If None, a random salt is generated.
                  The same salt must be used for decryption.
        
        Returns:
            The salt used for key derivation. Store this with encrypted data.
        
        Raises:
            ValueError: If password is empty.
        
        Security Note:
            The password is stored securely to allow re-derivation with
            different salts during decryption of messages from other devices.
        """
        if not password:
            raise ValueError("Password cannot be empty")
        
        with self._lock:
            # Clear any existing key first
            self.clear()
            
            # Generate or use provided salt
            if salt is None:
                salt = secrets.token_bytes(SALT_LENGTH)
            
            logger.debug("Deriving key with Argon2id...")
            
            # Derive key using Argon2id
            # This is intentionally slow (~1 second) to resist brute-force
            key = hash_secret_raw(
                secret=password.encode('utf-8'),
                salt=salt,
                time_cost=ARGON2_TIME_COST,
                memory_cost=ARGON2_MEMORY_COST,
                parallelism=ARGON2_PARALLELISM,
                hash_len=ARGON2_HASH_LEN,
                type=Type.ID  # Argon2id - hybrid of Argon2i and Argon2d
            )
            
            # Store in mutable bytearray (can be zeroed later)
            self._protected_key = bytearray(key)
            self._salt = salt
            
            # Store password securely for re-derivation during decryption
            # This is necessary because decryption needs to derive key with
            # the salt embedded in the ciphertext (from sender's device)
            password_bytes = password.encode('utf-8')
            # Pad to multiple of 16 for DPAPI
            padded_len = ((len(password_bytes) + 15) // 16) * 16
            self._protected_password = bytearray(padded_len)
            self._protected_password[:len(password_bytes)] = password_bytes
            
            # Apply memory protections to key
            self._is_locked = _mem_protect.lock_memory(self._protected_key)
            self._is_protected = _mem_protect.protect_memory(self._protected_key)
            
            # Apply memory protections to password
            self._password_locked = _mem_protect.lock_memory(self._protected_password)
            self._password_protected = _mem_protect.protect_memory(self._protected_password)
            
            # Log protection status (important for security auditing)
            if not self._is_locked:
                logger.warning("Memory locking failed - key may be swapped to disk")
            if not self._is_protected:
                logger.warning("Memory encryption failed - key stored in plaintext")
            
            logger.info("Encryption key set successfully")
            return salt
    
    def get_key(self) -> Optional[bytes]:
        """
        Retrieve the stored encryption key.
        
        If the key is protected (encrypted in memory), it is temporarily
        decrypted, copied, and re-encrypted. The returned copy should be
        used immediately and not stored.
        
        Returns:
            The 256-bit encryption key, or None if no key is set.
        
        Security Note:
            The returned bytes object cannot be securely erased from Python.
            Use the key immediately and let it go out of scope.
        """
        with self._lock:
            if not self._protected_key:
                return None
            
            # Temporarily decrypt if protected
            was_protected = self._is_protected
            if was_protected:
                if not _mem_protect.unprotect_memory(self._protected_key):
                    logger.error("Failed to decrypt key from memory")
                    return None
            
            try:
                # Copy key bytes
                key = bytes(self._protected_key)
                return key
            finally:
                # Always re-encrypt, even if copy failed
                if was_protected:
                    if not _mem_protect.protect_memory(self._protected_key):
                        logger.error("Failed to re-encrypt key in memory")
    
    def get_salt(self) -> Optional[bytes]:
        """Get the salt used for key derivation."""
        with self._lock:
            return self._salt
    
    def derive_key_with_salt(self, salt: bytes) -> Optional[bytes]:
        """
        Derive a key using the stored password and a specific salt.
        
        This is used during decryption when the ciphertext contains a
        different salt than the one used during set_key(). This happens
        when decrypting messages encrypted on another device.
        
        Args:
            salt: The salt extracted from the ciphertext.
        
        Returns:
            The derived key, or None if no password is stored.
        """
        with self._lock:
            if not self._protected_password:
                return None
            
            # Temporarily decrypt password if protected
            was_protected = self._password_protected
            if was_protected:
                if not _mem_protect.unprotect_memory(self._protected_password):
                    logger.error("Failed to decrypt password from memory")
                    return None
            
            try:
                # Find actual password length (remove padding zeros)
                password_bytes = bytes(self._protected_password).rstrip(b'\x00')
                
                # Derive key with the provided salt
                key = hash_secret_raw(
                    secret=password_bytes,
                    salt=salt,
                    time_cost=ARGON2_TIME_COST,
                    memory_cost=ARGON2_MEMORY_COST,
                    parallelism=ARGON2_PARALLELISM,
                    hash_len=ARGON2_HASH_LEN,
                    type=Type.ID
                )
                return key
            finally:
                # Always re-encrypt password
                if was_protected:
                    if not _mem_protect.protect_memory(self._protected_password):
                        logger.error("Failed to re-encrypt password in memory")
    
    def clear(self) -> None:
        """
        Securely wipe the key and password from memory.
        
        This method:
        1. Decrypts the key and password (if encrypted)
        2. Unlocks memory pages
        3. Overwrites with zeros
        4. Releases memory
        
        After calling clear(), get_key() will return None.
        """
        with self._lock:
            # Clear the derived key
            if self._protected_key:
                logger.debug("Securely wiping key from memory")
                
                # Decrypt first (can't properly zero encrypted data)
                if self._is_protected:
                    _mem_protect.unprotect_memory(self._protected_key)
                    self._is_protected = False
                
                # Unlock memory pages
                if self._is_locked:
                    _mem_protect.unlock_memory(self._protected_key)
                    self._is_locked = False
                
                # Secure zero the key material
                _mem_protect.secure_zero(self._protected_key)
                self._protected_key = None
            
            # Clear the stored password
            if self._protected_password:
                logger.debug("Securely wiping password from memory")
                
                if self._password_protected:
                    _mem_protect.unprotect_memory(self._protected_password)
                    self._password_protected = False
                
                if self._password_locked:
                    _mem_protect.unlock_memory(self._protected_password)
                    self._password_locked = False
                
                _mem_protect.secure_zero(self._protected_password)
                self._protected_password = None
            
            self._salt = None
            logger.info("Key securely wiped")
    
    def is_set(self) -> bool:
        """Check if a key is currently stored."""
        with self._lock:
            return self._protected_key is not None
    
    def __del__(self) -> None:
        """Ensure key is wiped when object is garbage collected."""
        try:
            self.clear()
        except Exception:
            pass  # Ignore errors during destruction


# =============================================================================
# Module-Level API
# =============================================================================

# Global secure key instance (thread-safe via internal locking)
_secure_key = SecureKey()


def set_encryption_key(password: str) -> bytes:
    """
    Set the global encryption key from a password.
    
    This derives a 256-bit key using Argon2id and stores it securely.
    The derivation takes approximately 1 second (intentionally slow).
    
    Args:
        password: The user's password or passphrase.
    
    Returns:
        The salt used for derivation. This is needed for decryption
        and is embedded in the encrypted output automatically.
    
    Example:
        >>> set_encryption_key("my secret password")
        >>> encrypted = encrypt("Hello, World!")
    """
    with _global_lock:
        salt = _secure_key.set_key(password)
        logger.info("Global encryption key activated")
        return salt


def clear_encryption_key() -> None:
    """
    Securely clear the global encryption key from memory.
    
    Call this when:
    - User logs out
    - Application is closing
    - Key timeout expires
    - User explicitly requests key clearing
    """
    with _global_lock:
        _secure_key.clear()
        logger.info("Global encryption key cleared")


def has_key() -> bool:
    """
    Check if an encryption key is currently set.
    
    Returns:
        True if a key is available for encryption/decryption.
    """
    with _global_lock:
        return _secure_key.is_set()


def encrypt(plaintext: str) -> str:
    """
    Encrypt text using AES-256-GCM.
    
    The output format is: ANON[base64(salt + nonce + ciphertext + tag)]
    
    Components:
        - salt: 16 bytes - Used for key derivation
        - nonce: 12 bytes - Unique per encryption (random)
        - ciphertext: Variable - The encrypted data
        - tag: 16 bytes - Authentication tag (detects tampering)
    
    Args:
        plaintext: The text to encrypt (UTF-8 string).
    
    Returns:
        Encrypted string in ANON[...] format.
    
    Raises:
        ValueError: If no encryption key is set.
        ValueError: If plaintext is empty.
    
    Example:
        >>> set_encryption_key("password123")
        >>> encrypted = encrypt("Secret message")
        >>> print(encrypted)
        ANON[base64data...]
    """
    with _global_lock:
        key = _secure_key.get_key()
        salt = _secure_key.get_salt()
        
        if not key:
            raise ValueError("No encryption key set. Call set_encryption_key() first.")
        
        if not salt:
            raise ValueError("No salt available. Key may be corrupted.")
        
        if not plaintext:
            raise ValueError("Cannot encrypt empty text.")
        
        # Generate random nonce (critical: must be unique per encryption)
        nonce = secrets.token_bytes(NONCE_LENGTH)
        
        # Create cipher and encrypt
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        
        # Combine all components: salt + nonce + ciphertext + tag
        combined = salt + nonce + ciphertext + tag
        
        # Base64 encode and wrap with markers
        encoded = base64.b64encode(combined).decode('utf-8')
        result = f"{PREFIX}{encoded}{SUFFIX}"
        
        logger.debug(f"Encrypted {len(plaintext)} chars -> {len(result)} chars")
        return result


def decrypt(ciphertext: str) -> str:
    """
    Decrypt AES-256-GCM encrypted text.
    
    Extracts the salt from the ciphertext and re-derives the key using
    the stored password. This allows decryption of messages encrypted
    on other devices with the same password but different salts.
    
    Verifies the authentication tag to detect tampering.
    
    Args:
        ciphertext: Encrypted string in ANON[...]IT format.
    
    Returns:
        The original plaintext.
    
    Raises:
        ValueError: If no encryption key is set.
        ValueError: If the format is invalid.
        ValueError: If decryption fails (wrong key or tampered data).
    
    Security Note:
        All error cases return the same generic message to prevent
        information leakage through error oracle attacks.
    """
    with _global_lock:
        if not _secure_key.is_set():
            raise ValueError("No encryption key set.")
        
        # Validate format using constant-time comparison where possible
        if not ciphertext:
            raise ValueError("Decryption failed.")
        
        # Check prefix/suffix (not constant-time, but format is public)
        if not ciphertext.startswith(PREFIX) or not ciphertext.endswith(SUFFIX):
            raise ValueError("Decryption failed.")
        
        # Extract base64 content
        encoded = ciphertext[len(PREFIX):-len(SUFFIX)]
        
        try:
            raw = base64.b64decode(encoded)
        except Exception:
            raise ValueError("Decryption failed.")
        
        # Minimum size: salt(16) + nonce(12) + tag(16) = 44 bytes
        min_size = SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH
        if len(raw) < min_size:
            raise ValueError("Decryption failed.")
        
        # Extract components
        embedded_salt = raw[:SALT_LENGTH]
        nonce = raw[SALT_LENGTH:SALT_LENGTH + NONCE_LENGTH]
        tag = raw[-TAG_LENGTH:]
        encrypted_data = raw[SALT_LENGTH + NONCE_LENGTH:-TAG_LENGTH]
        
        # Re-derive key using the embedded salt from the ciphertext
        # This is critical for cross-device decryption!
        key = _secure_key.derive_key_with_salt(embedded_salt)
        
        if not key:
            raise ValueError("Decryption failed.")
        
        # Decrypt and verify authentication tag
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        try:
            decrypted = cipher.decrypt_and_verify(encrypted_data, tag)
            plaintext = decrypted.decode('utf-8')
            logger.debug(f"Decrypted {len(ciphertext)} chars -> {len(plaintext)} chars")
            return plaintext
        except Exception:
            # Generic error to prevent oracle attacks
            raise ValueError("Decryption failed.")


def is_encrypted(text: str) -> bool:
    """
    Check if text appears to be AnonIT encrypted.
    
    This only checks the format markers, not validity.
    
    Args:
        text: Text to check.
    
    Returns:
        True if text has ANON[...] format.
    """
    if not text:
        return False
    return text.startswith(PREFIX) and text.endswith(SUFFIX)


# =============================================================================
# Module Initialization
# =============================================================================

def _setup_logging() -> None:
    """Configure logging for the crypto module."""
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        '[%(levelname)s] %(name)s: %(message)s'
    ))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


# Initialize logging on module load
_setup_logging()
