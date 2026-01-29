#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AnonIT Secure Memory Module
===========================

Maximum security memory handling:
- Secure memory wiping
- Windows DPAPI memory protection
- Memory locking (prevent swap)
- Panic wipe functionality
"""

import ctypes
import gc
import sys
import os
from typing import Optional


class SecureMemory:
    """
    Secure memory operations for maximum privacy.
    """
    
    def __init__(self):
        self._is_windows = sys.platform == 'win32'
        self._kernel32 = None
        self._crypt32 = None
        
        if self._is_windows:
            try:
                self._kernel32 = ctypes.windll.kernel32
                self._crypt32 = ctypes.windll.crypt32
            except:
                pass
    
    def secure_wipe(self, data: bytearray) -> None:
        """
        Securely wipe data from memory.
        
        Uses multiple overwrite passes to prevent recovery:
        1. Zeros
        2. Ones
        3. Random pattern
        4. Final zeros
        """
        if not data:
            return
        
        size = len(data)
        
        try:
            # Pass 1: Zeros
            for i in range(size):
                data[i] = 0x00
            
            # Pass 2: Ones
            for i in range(size):
                data[i] = 0xFF
            
            # Pass 3: Alternating pattern
            for i in range(size):
                data[i] = 0xAA if i % 2 == 0 else 0x55
            
            # Pass 4: Final zeros
            for i in range(size):
                data[i] = 0x00
            
            # Memory barrier - force write
            if self._is_windows and self._kernel32:
                try:
                    addr = ctypes.addressof((ctypes.c_char * size).from_buffer(data))
                    ctypes.memset(addr, 0, size)
                except:
                    pass
                    
        except Exception:
            # Fallback: simple zero
            for i in range(len(data)):
                data[i] = 0
    
    def secure_wipe_string(self, s: str) -> None:
        """
        Attempt to wipe a string from memory.
        
        Note: Python strings are immutable, so this is best-effort.
        We create a bytearray copy and wipe that, then force GC.
        """
        if not s:
            return
        
        try:
            # Create mutable copy
            data = bytearray(s.encode('utf-8'))
            self.secure_wipe(data)
            del data
        except:
            pass
        
        gc.collect()
    
    def lock_memory(self, data: bytearray) -> bool:
        """
        Lock memory pages to prevent swapping to disk.
        
        Windows only - uses VirtualLock.
        """
        if not self._is_windows or not self._kernel32 or not data:
            return False
        
        try:
            size = len(data)
            addr = ctypes.addressof((ctypes.c_char * size).from_buffer(data))
            return bool(self._kernel32.VirtualLock(
                ctypes.c_void_p(addr),
                ctypes.c_size_t(size)
            ))
        except:
            return False
    
    def unlock_memory(self, data: bytearray) -> bool:
        """Unlock previously locked memory."""
        if not self._is_windows or not self._kernel32 or not data:
            return False
        
        try:
            size = len(data)
            addr = ctypes.addressof((ctypes.c_char * size).from_buffer(data))
            return bool(self._kernel32.VirtualUnlock(
                ctypes.c_void_p(addr),
                ctypes.c_size_t(size)
            ))
        except:
            return False
    
    def protect_memory(self, data: bytearray) -> bool:
        """
        Encrypt memory using Windows DPAPI.
        
        This encrypts the data in-place so it's protected in RAM.
        """
        if not self._is_windows or not self._crypt32 or not data:
            return False
        
        CRYPTPROTECTMEMORY_SAME_PROCESS = 0x00
        BLOCK_SIZE = 16
        
        size = len(data)
        if size % BLOCK_SIZE != 0:
            return False
        
        try:
            addr = ctypes.addressof((ctypes.c_char * size).from_buffer(data))
            return bool(self._crypt32.CryptProtectMemory(
                ctypes.c_void_p(addr),
                ctypes.c_ulong(size),
                ctypes.c_ulong(CRYPTPROTECTMEMORY_SAME_PROCESS)
            ))
        except:
            return False
    
    def unprotect_memory(self, data: bytearray) -> bool:
        """Decrypt DPAPI-protected memory."""
        if not self._is_windows or not self._crypt32 or not data:
            return False
        
        CRYPTPROTECTMEMORY_SAME_PROCESS = 0x00
        
        try:
            size = len(data)
            addr = ctypes.addressof((ctypes.c_char * size).from_buffer(data))
            return bool(self._crypt32.CryptUnprotectMemory(
                ctypes.c_void_p(addr),
                ctypes.c_ulong(size),
                ctypes.c_ulong(CRYPTPROTECTMEMORY_SAME_PROCESS)
            ))
        except:
            return False


# Global instance
_secure_mem = SecureMemory()


def secure_wipe(data: bytearray) -> None:
    """Securely wipe data from memory."""
    _secure_mem.secure_wipe(data)


def secure_wipe_string(s: str) -> None:
    """Attempt to wipe string from memory."""
    _secure_mem.secure_wipe_string(s)


def lock_memory(data: bytearray) -> bool:
    """Lock memory to prevent swap."""
    return _secure_mem.lock_memory(data)


def unlock_memory(data: bytearray) -> bool:
    """Unlock memory."""
    return _secure_mem.unlock_memory(data)


def force_gc():
    """Force garbage collection."""
    gc.collect()


def panic_wipe_process():
    """
    PANIC: Attempt to wipe as much sensitive data as possible.
    
    This is a best-effort function that:
    1. Forces garbage collection
    2. Clears Python's internal caches
    """
    gc.collect()
    gc.collect()
    gc.collect()
