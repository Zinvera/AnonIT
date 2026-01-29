#!/usr/bin/env python3
"""
Test script for AnonIT Messenger
Tests connection, key exchange, and message sending between two clients.
"""

import time
import sys
import os
import shutil
import tempfile

sys.path.insert(0, '.')

SERVER = "ws://localhost:8765"


def test_basic_connection():
    """Test basic server connection."""
    print("\n=== Test 1: Basic Connection ===")
    
    from messenger.client import MessengerClient
    
    client = MessengerClient(SERVER)
    client.start()
    
    time.sleep(3)
    
    if client.connected:
        print(f"✅ Connected! User ID: {client.user_id}")
        client.stop()
        time.sleep(0.5)
        print("✅ Disconnected cleanly")
        return True
    else:
        print("❌ Connection failed!")
        client.stop()
        return False


def test_two_clients():
    """Test two clients communicating with separate identities."""
    print("\n=== Test 2: Two Clients Communication ===")
    
    # Create separate data directories for each client
    temp_dir_a = tempfile.mkdtemp(prefix="anonit_a_")
    temp_dir_b = tempfile.mkdtemp(prefix="anonit_b_")
    
    print(f"  Client A data: {temp_dir_a}")
    print(f"  Client B data: {temp_dir_b}")
    
    try:
        # Import with fresh protocol instances
        from messenger.protocol import MessengerProtocol
        from messenger.client import MessengerClient, Contact, Message
        from pathlib import Path
        
        # Create clients with separate identities
        class TestClient(MessengerClient):
            def __init__(self, server_url, data_dir):
                # Override protocol with custom data dir
                from messenger.protocol import MessengerProtocol
                super().__init__(server_url)
                self.protocol = MessengerProtocol(data_dir=Path(data_dir))
        
        client_a = TestClient(SERVER, temp_dir_a)
        client_b = TestClient(SERVER, temp_dir_b)
        
        received_messages = []
        
        def on_message_b(peer_id, msg):
            print(f"  📨 Client B received: '{msg.content}'")
            received_messages.append(msg.content)
        
        client_b.on_message = on_message_b
        
        # Start both
        print("  Starting clients...")
        client_a.start()
        time.sleep(2)
        client_b.start()
        time.sleep(3)
        
        if not client_a.connected:
            print(f"❌ Client A not connected")
            return False
        if not client_b.connected:
            print(f"❌ Client B not connected")
            return False
        
        print(f"✅ Client A: {client_a.user_id[:16]}...")
        print(f"✅ Client B: {client_b.user_id[:16]}...")
        
        if client_a.user_id == client_b.user_id:
            print("❌ ERROR: Both clients have same ID!")
            return False
        
        # Add contacts
        print("\n  Adding contacts...")
        client_a.add_contact(client_b.user_id)
        client_b.add_contact(client_a.user_id)
        
        time.sleep(3)
        
        # Check keys
        if client_b.user_id in client_a.contacts:
            contact = client_a.contacts[client_b.user_id]
            if contact.public_key:
                print(f"✅ Client A has Client B's keys")
            else:
                print("⚠ Waiting for keys...")
                time.sleep(3)
        
        # Send message
        print("\n  Sending test message A → B...")
        test_msg = "Hello from Client A!"
        
        success = client_a.send_message(client_b.user_id, test_msg)
        
        if success:
            print(f"✅ Message queued")
        else:
            print("⚠ First attempt failed, retrying...")
            time.sleep(3)
            success = client_a.send_message(client_b.user_id, test_msg)
            if success:
                print(f"✅ Message sent on retry")
        
        # Wait for delivery
        print("  Waiting for delivery...")
        time.sleep(4)
        
        if test_msg in received_messages:
            print(f"✅ SUCCESS: Message received and decrypted!")
            result = True
        else:
            print(f"⚠ Message not received (got: {received_messages})")
            result = False
        
        # Cleanup
        print("\n  Cleaning up...")
        client_a.stop()
        client_b.stop()
        time.sleep(1)
        
        return result
        
    finally:
        # Remove temp directories
        shutil.rmtree(temp_dir_a, ignore_errors=True)
        shutil.rmtree(temp_dir_b, ignore_errors=True)


def main():
    print("=" * 50)
    print("  AnonIT Messenger Test Suite")
    print("=" * 50)
    
    # Test 1
    if not test_basic_connection():
        print("\n❌ Basic connection test failed!")
        return
    
    # Test 2
    success = test_two_clients()
    
    print("\n" + "=" * 50)
    if success:
        print("  ✅ ALL TESTS PASSED!")
    else:
        print("  ⚠ Some tests had issues")
    print("=" * 50)


if __name__ == "__main__":
    main()
