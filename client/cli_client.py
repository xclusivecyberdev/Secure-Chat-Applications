#!/usr/bin/env python3
"""
CLI Client for End-to-End Encrypted Chat

Provides a command-line interface for:
- User registration and login
- Secure key exchange using X3DH
- Encrypted messaging using Double Ratchet
- Local encrypted message history
"""

import asyncio
import json
import sys
import getpass
from typing import Optional, Dict
from datetime import datetime
import websockets
import httpx
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout

from crypto.x3dh import X3DHKeyExchange, PreKeyBundle
from crypto.double_ratchet import DoubleRatchet
from crypto.primitives import (
    serialize_public_key,
    serialize_identity_public_key,
    deserialize_public_key,
    CryptoError
)
from client.storage import EncryptedStorage


class ChatClient:
    """
    End-to-end encrypted chat client.
    """

    def __init__(self, server_url: str = "http://localhost:8000"):
        """
        Initialize chat client.

        Args:
            server_url: Base URL of the chat server
        """
        self.server_url = server_url
        self.ws_url = server_url.replace("http", "ws") + "/ws"
        self.username: Optional[str] = None
        self.token: Optional[str] = None
        self.storage: Optional[EncryptedStorage] = None
        self.x3dh = X3DHKeyExchange()
        self.sessions: Dict[str, DoubleRatchet] = {}
        self.websocket: Optional[websockets.WebSocketClientProtocol] = None
        self.http_client = httpx.AsyncClient()
        self.running = False
        self.current_chat: Optional[str] = None

    async def register(self, username: str, password: str) -> bool:
        """
        Register a new user account.

        Args:
            username: Desired username
            password: Password

        Returns:
            True if successful
        """
        # Generate identity keys
        identity_public = self.x3dh.generate_identity_keys()

        try:
            response = await self.http_client.post(
                f"{self.server_url}/api/register",
                json={
                    "username": username,
                    "password": password,
                    "identity_key": identity_public.hex()
                }
            )

            if response.status_code == 200:
                data = response.json()
                self.token = data["access_token"]
                self.username = username

                # Initialize storage
                self.storage = EncryptedStorage(username)
                if not self.storage.unlock(password):
                    print("Failed to unlock storage")
                    return False

                # Save identity keys
                self.storage.save_keys("identity", {
                    "public": identity_public.hex(),
                    # Note: We don't serialize private keys directly for security
                })

                # Generate and upload prekeys
                await self._generate_and_upload_prekeys()

                print(f"Registration successful! Welcome, {username}")
                return True
            else:
                error = response.json()
                print(f"Registration failed: {error.get('detail', 'Unknown error')}")
                return False

        except Exception as e:
            print(f"Registration error: {e}")
            return False

    async def login(self, username: str, password: str) -> bool:
        """
        Login with existing account.

        Args:
            username: Username
            password: Password

        Returns:
            True if successful
        """
        try:
            response = await self.http_client.post(
                f"{self.server_url}/api/login",
                json={
                    "username": username,
                    "password": password
                }
            )

            if response.status_code == 200:
                data = response.json()
                self.token = data["access_token"]
                self.username = username

                # Initialize storage
                self.storage = EncryptedStorage(username)
                if not self.storage.unlock(password):
                    print("Failed to unlock storage with this password")
                    return False

                # Restore X3DH keys (we need to regenerate for this session)
                # In production, you'd serialize/deserialize the private keys securely
                self.x3dh.generate_identity_keys()

                print(f"Login successful! Welcome back, {username}")
                return True
            else:
                error = response.json()
                print(f"Login failed: {error.get('detail', 'Unknown error')}")
                return False

        except Exception as e:
            print(f"Login error: {e}")
            return False

    async def _generate_and_upload_prekeys(self):
        """Generate prekeys and upload to server"""
        bundle = self.x3dh.generate_prekeys(num_one_time_keys=10)

        # Upload to server
        try:
            response = await self.http_client.post(
                f"{self.server_url}/api/prekeys/{self.username}",
                json={
                    "signed_pre_key": bundle.signed_pre_key.hex(),
                    "one_time_pre_keys": [bundle.one_time_pre_key.hex()] if bundle.one_time_pre_key else []
                },
                headers={"Authorization": f"Bearer {self.token}"}
            )

            if response.status_code == 200:
                # Save prekeys locally
                self.storage.save_keys("prekeys", {
                    "signed_pre_key": bundle.signed_pre_key.hex(),
                })
        except Exception as e:
            print(f"Failed to upload prekeys: {e}")

    async def connect_websocket(self):
        """Connect to WebSocket server"""
        try:
            self.websocket = await websockets.connect(self.ws_url)

            # Authenticate
            await self.websocket.send(json.dumps({
                "type": "auth",
                "token": self.token
            }))

            # Wait for auth response
            response = await self.websocket.recv()
            data = json.loads(response)

            if data.get("type") == "auth_success":
                print("Connected to server")
                print(f"Online users: {', '.join(data.get('online_users', []))}")
                return True
            else:
                print("Authentication failed")
                return False

        except Exception as e:
            print(f"WebSocket connection error: {e}")
            return False

    async def start_chat(self, peer_username: str):
        """
        Start or continue a chat with a user.

        Args:
            peer_username: Username to chat with
        """
        self.current_chat = peer_username

        # Load or create session
        if peer_username not in self.sessions:
            session_state = self.storage.load_session(peer_username)
            if session_state:
                # Restore existing session
                self.sessions[peer_username] = DoubleRatchet.import_state(session_state)
                print(f"Restored session with {peer_username}")
            else:
                # Initialize new session with X3DH
                await self._initialize_session(peer_username)

        # Load message history
        messages = self.storage.get_messages(peer_username, limit=20)
        if messages:
            print("\n--- Message History ---")
            for msg in messages:
                prefix = "You" if msg['direction'] == 'sent' else peer_username
                timestamp = datetime.fromisoformat(msg['timestamp']).strftime("%H:%M")
                print(f"[{timestamp}] {prefix}: {msg['content']}")
            print("--- End History ---\n")

        print(f"Chatting with {peer_username}. Type '/exit' to leave chat, '/help' for commands.")

    async def _initialize_session(self, peer_username: str):
        """
        Initialize a new encrypted session using X3DH.

        Args:
            peer_username: Peer to initialize session with
        """
        try:
            # Fetch peer's prekey bundle
            response = await self.http_client.get(
                f"{self.server_url}/api/prekeys/{peer_username}"
            )

            if response.status_code != 200:
                print(f"Failed to get prekeys for {peer_username}")
                return

            bundle_data = response.json()
            peer_bundle = PreKeyBundle.from_dict(bundle_data)

            # Perform X3DH
            result = self.x3dh.initiate_session(peer_bundle, self.x3dh.identity_private)

            # Create Double Ratchet session
            self.sessions[peer_username] = DoubleRatchet(result.shared_key, sending=True)

            # Save session
            self.storage.save_session(peer_username, self.sessions[peer_username].export_state())

            print(f"Initialized encrypted session with {peer_username}")

        except Exception as e:
            print(f"Failed to initialize session: {e}")

    async def send_message(self, peer: str, message: str):
        """
        Send an encrypted message.

        Args:
            peer: Recipient username
            message: Message to send
        """
        if peer not in self.sessions:
            print("No session with this user. Starting chat first...")
            return

        try:
            # Encrypt message
            encrypted = self.sessions[peer].encrypt(message.encode())

            # Send via WebSocket
            await self.websocket.send(json.dumps({
                "type": "message",
                "to": peer,
                "data": encrypted
            }))

            # Save to history
            self.storage.save_message(peer, message, "sent")

            # Update session state
            self.storage.save_session(peer, self.sessions[peer].export_state())

        except Exception as e:
            print(f"Failed to send message: {e}")

    async def receive_messages(self):
        """Background task to receive messages"""
        try:
            while self.running:
                message = await self.websocket.recv()
                data = json.loads(message)

                if data.get("type") == "message":
                    await self._handle_incoming_message(data)
                elif data.get("type") == "user_online":
                    print(f"\n[{data['username']} is now online]")
                elif data.get("type") == "user_offline":
                    print(f"\n[{data['username']} is now offline]")
                elif data.get("type") == "error":
                    print(f"\n[Error: {data.get('message')}]")

        except websockets.exceptions.ConnectionClosed:
            print("\nConnection closed")
            self.running = False
        except Exception as e:
            print(f"\nReceive error: {e}")
            self.running = False

    async def _handle_incoming_message(self, data: dict):
        """Handle incoming encrypted message"""
        sender = data.get("from")
        encrypted_data = data.get("data")

        if not sender or not encrypted_data:
            return

        try:
            # Check if we have a session
            if sender not in self.sessions:
                # Initialize receiver session
                session_state = self.storage.load_session(sender)
                if session_state:
                    self.sessions[sender] = DoubleRatchet.import_state(session_state)
                else:
                    # Create new receiving session
                    # First message needs to initialize the ratchet
                    # We use a placeholder shared key (in real app, would need X3DH from sender)
                    # For simplicity, we'll need the receiver to also have performed X3DH
                    # This is a limitation of this simplified implementation

                    # Fetch our prekeys to complete X3DH
                    shared_key = await self._complete_x3dh_receiver(sender, encrypted_data)
                    if not shared_key:
                        print(f"\n[Failed to establish session with {sender}]")
                        return

                    self.sessions[sender] = DoubleRatchet(shared_key, sending=False)
                    self.sessions[sender].initialize_receiver(encrypted_data)

            # Decrypt message
            plaintext = self.sessions[sender].decrypt(encrypted_data)
            message = plaintext.decode()

            # Save to history
            self.storage.save_message(sender, message, "received")

            # Update session
            self.storage.save_session(sender, self.sessions[sender].export_state())

            # Display message
            timestamp = datetime.now().strftime("%H:%M")
            if sender == self.current_chat:
                print(f"\n[{timestamp}] {sender}: {message}")
            else:
                print(f"\n[New message from {sender}]: {message}")

        except CryptoError as e:
            print(f"\n[Failed to decrypt message from {sender}: {e}]")
        except Exception as e:
            print(f"\n[Error handling message from {sender}: {e}]")

    async def _complete_x3dh_receiver(self, sender: str, initial_message: dict) -> Optional[bytes]:
        """
        Complete X3DH as receiver.

        This is a simplified version - in production, would need more robust key agreement.
        """
        # For now, return None to indicate we need proper X3DH setup
        # In a full implementation, the receiver would compute the shared secret
        # from their prekeys and the sender's ephemeral key
        return None

    async def list_users(self):
        """List all registered users"""
        try:
            response = await self.http_client.get(f"{self.server_url}/api/users")
            if response.status_code == 200:
                users = response.json()["users"]
                print("Registered users:")
                for user in users:
                    print(f"  - {user}")
        except Exception as e:
            print(f"Failed to list users: {e}")

    async def list_online_users(self):
        """List currently online users"""
        try:
            response = await self.http_client.get(f"{self.server_url}/api/users/online")
            if response.status_code == 200:
                users = response.json()["users"]
                print("Online users:")
                for user in users:
                    if user != self.username:
                        print(f"  - {user}")
        except Exception as e:
            print(f"Failed to list online users: {e}")

    async def run_interactive(self):
        """Run interactive chat session"""
        self.running = True

        # Start receive task
        receive_task = asyncio.create_task(self.receive_messages())

        # Interactive prompt
        session = PromptSession()

        print("\nCommands:")
        print("  /chat <username> - Start chat with user")
        print("  /exit - Exit current chat")
        print("  /users - List all users")
        print("  /online - List online users")
        print("  /history - Show conversation list")
        print("  /quit - Quit application")
        print()

        try:
            while self.running:
                try:
                    if self.current_chat:
                        prompt_text = f"[{self.current_chat}] > "
                    else:
                        prompt_text = "> "

                    with patch_stdout():
                        user_input = await session.prompt_async(prompt_text)

                    if not user_input:
                        continue

                    if user_input.startswith("/"):
                        await self._handle_command(user_input)
                    elif self.current_chat:
                        await self.send_message(self.current_chat, user_input)
                    else:
                        print("No active chat. Use /chat <username> to start.")

                except KeyboardInterrupt:
                    break
                except EOFError:
                    break

        finally:
            self.running = False
            receive_task.cancel()
            if self.websocket:
                await self.websocket.close()
            await self.http_client.aclose()
            if self.storage:
                self.storage.close()

    async def _handle_command(self, command: str):
        """Handle slash commands"""
        parts = command.split(maxsplit=1)
        cmd = parts[0].lower()

        if cmd == "/chat" and len(parts) == 2:
            await self.start_chat(parts[1])
        elif cmd == "/exit":
            self.current_chat = None
            print("Exited chat")
        elif cmd == "/users":
            await self.list_users()
        elif cmd == "/online":
            await self.list_online_users()
        elif cmd == "/history":
            if self.storage:
                convos = self.storage.list_conversations()
                print("Conversations:")
                for convo in convos:
                    print(f"  - {convo}")
        elif cmd == "/quit":
            self.running = False
        elif cmd == "/help":
            print("Commands:")
            print("  /chat <username> - Start chat with user")
            print("  /exit - Exit current chat")
            print("  /users - List all users")
            print("  /online - List online users")
            print("  /history - Show conversation list")
            print("  /quit - Quit application")
        else:
            print("Unknown command. Type /help for help.")


async def main():
    """Main entry point"""
    client = ChatClient()

    print("=" * 50)
    print("End-to-End Encrypted Chat Client")
    print("=" * 50)
    print()

    while True:
        print("1. Register")
        print("2. Login")
        print("3. Quit")
        choice = input("Choose an option: ").strip()

        if choice == "1":
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ")
            if await client.register(username, password):
                break
        elif choice == "2":
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ")
            if await client.login(username, password):
                break
        elif choice == "3":
            return
        else:
            print("Invalid choice")

    # Connect WebSocket
    if await client.connect_websocket():
        # Run interactive session
        await client.run_interactive()

    print("\nGoodbye!")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted")
        sys.exit(0)
