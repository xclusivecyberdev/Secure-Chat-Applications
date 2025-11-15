"""
Encrypted local storage for chat client.

Stores message history, session states, and keys encrypted on disk.
"""

import os
import json
import sqlite3
from typing import Optional, List, Dict
from pathlib import Path
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import getpass


class EncryptedStorage:
    """
    Manages encrypted local storage for chat data.

    All data is encrypted with a key derived from the user's password.
    """

    def __init__(self, username: str, storage_dir: str = "client_data"):
        """
        Initialize encrypted storage.

        Args:
            username: Username for this storage
            storage_dir: Directory to store encrypted data
        """
        self.username = username
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(exist_ok=True)

        self.db_path = self.storage_dir / f"{username}.db"
        self.encryption_key: Optional[bytes] = None
        self.db: Optional[sqlite3.Connection] = None

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2.

        Args:
            password: User's password
            salt: Salt for key derivation

        Returns:
            32-byte encryption key
        """
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password.encode())

    def unlock(self, password: str) -> bool:
        """
        Unlock storage with password.

        Args:
            password: User's password

        Returns:
            True if unlocked successfully
        """
        # Check if database exists
        if not self.db_path.exists():
            # Create new database
            salt = os.urandom(16)
            self.encryption_key = self.derive_key(password, salt)

            # Save salt
            salt_file = self.storage_dir / f"{self.username}.salt"
            with open(salt_file, "wb") as f:
                f.write(salt)

            self._init_database()
            return True
        else:
            # Load existing database
            salt_file = self.storage_dir / f"{self.username}.salt"
            if not salt_file.exists():
                return False

            with open(salt_file, "rb") as f:
                salt = f.read()

            self.encryption_key = self.derive_key(password, salt)
            self._init_database()

            # Verify password by trying to read a test value
            try:
                self._get_metadata("test")
                return True
            except Exception:
                self.encryption_key = None
                return True  # New database

    def _init_database(self):
        """Initialize SQLite database"""
        self.db = sqlite3.connect(str(self.db_path))
        cursor = self.db.cursor()

        # Create tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_username TEXT NOT NULL,
                direction TEXT NOT NULL,
                encrypted_content BLOB NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                peer_username TEXT PRIMARY KEY,
                encrypted_state BLOB NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                encrypted_value BLOB NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                key_type TEXT PRIMARY KEY,
                encrypted_data BLOB NOT NULL
            )
        """)

        self.db.commit()

    def _encrypt(self, data: bytes) -> bytes:
        """Encrypt data with storage key"""
        if not self.encryption_key:
            raise ValueError("Storage not unlocked")

        nonce = os.urandom(12)
        aesgcm = AESGCM(self.encryption_key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext

    def _decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt data with storage key"""
        if not self.encryption_key:
            raise ValueError("Storage not unlocked")

        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        aesgcm = AESGCM(self.encryption_key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def save_message(self, peer: str, message: str, direction: str):
        """
        Save a message to history.

        Args:
            peer: Username of the peer
            message: Message content
            direction: 'sent' or 'received'
        """
        if not self.db:
            return

        encrypted = self._encrypt(message.encode())
        timestamp = datetime.utcnow().isoformat()

        cursor = self.db.cursor()
        cursor.execute(
            "INSERT INTO messages (peer_username, direction, encrypted_content, timestamp) VALUES (?, ?, ?, ?)",
            (peer, direction, encrypted, timestamp)
        )
        self.db.commit()

    def get_messages(self, peer: str, limit: int = 50) -> List[Dict]:
        """
        Get message history with a peer.

        Args:
            peer: Username of the peer
            limit: Maximum number of messages to retrieve

        Returns:
            List of message dictionaries
        """
        if not self.db:
            return []

        cursor = self.db.cursor()
        cursor.execute(
            "SELECT direction, encrypted_content, timestamp FROM messages WHERE peer_username = ? ORDER BY id DESC LIMIT ?",
            (peer, limit)
        )

        messages = []
        for direction, encrypted, timestamp in cursor.fetchall():
            try:
                content = self._decrypt(encrypted).decode()
                messages.append({
                    'direction': direction,
                    'content': content,
                    'timestamp': timestamp
                })
            except Exception:
                continue  # Skip corrupted messages

        return list(reversed(messages))

    def save_session(self, peer: str, session_state: str):
        """
        Save Double Ratchet session state.

        Args:
            peer: Username of the peer
            session_state: JSON-serialized session state
        """
        if not self.db:
            return

        encrypted = self._encrypt(session_state.encode())
        timestamp = datetime.utcnow().isoformat()

        cursor = self.db.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO sessions (peer_username, encrypted_state, updated_at) VALUES (?, ?, ?)",
            (peer, encrypted, timestamp)
        )
        self.db.commit()

    def load_session(self, peer: str) -> Optional[str]:
        """
        Load Double Ratchet session state.

        Args:
            peer: Username of the peer

        Returns:
            JSON-serialized session state or None
        """
        if not self.db:
            return None

        cursor = self.db.cursor()
        cursor.execute("SELECT encrypted_state FROM sessions WHERE peer_username = ?", (peer,))
        result = cursor.fetchone()

        if result:
            try:
                return self._decrypt(result[0]).decode()
            except Exception:
                return None

        return None

    def save_keys(self, key_type: str, key_data: dict):
        """
        Save cryptographic keys.

        Args:
            key_type: Type of keys ('identity', 'prekeys', etc.)
            key_data: Dictionary of key data
        """
        if not self.db:
            return

        encrypted = self._encrypt(json.dumps(key_data).encode())

        cursor = self.db.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO keys (key_type, encrypted_data) VALUES (?, ?)",
            (key_type, encrypted)
        )
        self.db.commit()

    def load_keys(self, key_type: str) -> Optional[dict]:
        """
        Load cryptographic keys.

        Args:
            key_type: Type of keys to load

        Returns:
            Dictionary of key data or None
        """
        if not self.db:
            return None

        cursor = self.db.cursor()
        cursor.execute("SELECT encrypted_data FROM keys WHERE key_type = ?", (key_type,))
        result = cursor.fetchone()

        if result:
            try:
                decrypted = self._decrypt(result[0])
                return json.loads(decrypted.decode())
            except Exception:
                return None

        return None

    def _get_metadata(self, key: str) -> Optional[str]:
        """Get metadata value"""
        if not self.db:
            return None

        cursor = self.db.cursor()
        cursor.execute("SELECT encrypted_value FROM metadata WHERE key = ?", (key,))
        result = cursor.fetchone()

        if result:
            return self._decrypt(result[0]).decode()
        return None

    def close(self):
        """Close database connection"""
        if self.db:
            self.db.close()
            self.db = None

    def list_conversations(self) -> List[str]:
        """
        List all users we have conversations with.

        Returns:
            List of usernames
        """
        if not self.db:
            return []

        cursor = self.db.cursor()
        cursor.execute("SELECT DISTINCT peer_username FROM messages")
        return [row[0] for row in cursor.fetchall()]
