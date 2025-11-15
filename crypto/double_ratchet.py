"""
Double Ratchet Algorithm

Implements the Double Ratchet algorithm for end-to-end encrypted messaging with
forward secrecy and break-in recovery. This algorithm combines a DH ratchet for
forward secrecy with a symmetric key ratchet for immediate key updates.
"""

import json
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .primitives import (
    generate_dh_keypair,
    dh_exchange,
    kdf_root,
    kdf_chain,
    encrypt_message,
    decrypt_message,
    serialize_public_key,
    deserialize_public_key,
    CryptoError
)


@dataclass
class RatchetState:
    """
    State of the Double Ratchet algorithm.

    Attributes:
        root_key: Root key for DH ratchet
        sending_chain_key: Current sending chain key
        receiving_chain_key: Current receiving chain key
        dh_private: Our current DH ratchet private key
        dh_public: Our current DH ratchet public key
        dh_remote_public: Remote party's current DH ratchet public key
        send_count: Number of messages sent in current chain
        recv_count: Number of messages received in current chain
        prev_send_count: Messages sent in previous chain
        skipped_keys: Dictionary of skipped message keys for out-of-order messages
    """
    root_key: bytes
    sending_chain_key: Optional[bytes]
    receiving_chain_key: Optional[bytes]
    dh_private: Optional[bytes]  # Serialized private key
    dh_public: Optional[bytes]
    dh_remote_public: Optional[bytes]
    send_count: int = 0
    recv_count: int = 0
    prev_send_count: int = 0
    skipped_keys: Dict[Tuple[bytes, int], bytes] = None

    def __post_init__(self):
        if self.skipped_keys is None:
            self.skipped_keys = {}


class DoubleRatchet:
    """
    Double Ratchet session for encrypted messaging.

    Provides forward secrecy and break-in recovery through:
    - DH ratchet: Updates DH keypair with each message exchange
    - Symmetric ratchet: Derives new chain keys for each message
    """

    MAX_SKIP = 1000  # Maximum number of message keys we'll skip and store

    def __init__(self, shared_key: bytes, sending: bool = True):
        """
        Initialize a Double Ratchet session.

        Args:
            shared_key: Initial shared secret from X3DH
            sending: True if we're initiating (sender), False if receiving
        """
        self.state = RatchetState(
            root_key=shared_key,
            sending_chain_key=None,
            receiving_chain_key=None,
            dh_private=None,
            dh_public=None,
            dh_remote_public=None,
            skipped_keys={}
        )

        if sending:
            # Initialize as sender - generate initial DH keypair
            self._init_sending_chain()

    def _init_sending_chain(self):
        """Initialize the sending chain with a new DH keypair"""
        private_key, public_key = generate_dh_keypair()
        self.state.dh_private = private_key.private_bytes_raw()
        self.state.dh_public = serialize_public_key(public_key)

    def _dh_ratchet_step(self, remote_public: bytes):
        """
        Perform a DH ratchet step.

        Args:
            remote_public: Remote party's public DH key
        """
        # Update to received remote public key
        self.state.dh_remote_public = remote_public

        # Perform DH with current private and new remote public
        if self.state.dh_private:
            private_key = X25519PrivateKey.from_private_bytes(self.state.dh_private)
            remote_public_key = deserialize_public_key(remote_public)
            dh_output = dh_exchange(private_key, remote_public_key)

            # Update root key and receiving chain
            self.state.root_key, self.state.receiving_chain_key = kdf_root(
                self.state.root_key, dh_output
            )
            self.state.recv_count = 0

        # Generate new DH keypair for sending
        new_private, new_public = generate_dh_keypair()
        self.state.dh_private = new_private.private_bytes_raw()
        self.state.dh_public = serialize_public_key(new_public)

        # Perform DH with new private and remote public
        remote_public_key = deserialize_public_key(remote_public)
        dh_output = dh_exchange(new_private, remote_public_key)

        # Update root key and sending chain
        self.state.root_key, self.state.sending_chain_key = kdf_root(
            self.state.root_key, dh_output
        )
        self.state.prev_send_count = self.state.send_count
        self.state.send_count = 0

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> Dict:
        """
        Encrypt a message.

        Args:
            plaintext: Message to encrypt
            associated_data: Additional authenticated data

        Returns:
            Dictionary containing encrypted message and header info
        """
        if self.state.sending_chain_key is None:
            raise CryptoError("Cannot encrypt without establishing session first")

        # Derive message key from sending chain
        self.state.sending_chain_key, message_key = kdf_chain(
            self.state.sending_chain_key,
            b"MessageKeys"
        )

        # Encrypt the message
        ciphertext = encrypt_message(message_key, plaintext, associated_data)

        # Create message header
        header = {
            'dh_public': self.state.dh_public.hex(),
            'prev_count': self.state.prev_send_count,
            'msg_num': self.state.send_count
        }

        self.state.send_count += 1

        return {
            'header': header,
            'ciphertext': ciphertext.hex()
        }

    def decrypt(self, message: Dict, associated_data: bytes = b"") -> bytes:
        """
        Decrypt a message.

        Args:
            message: Dictionary containing header and ciphertext
            associated_data: Additional authenticated data

        Returns:
            Decrypted plaintext

        Raises:
            CryptoError: If decryption fails
        """
        header = message['header']
        ciphertext = bytes.fromhex(message['ciphertext'])
        remote_public = bytes.fromhex(header['dh_public'])
        msg_num = header['msg_num']

        # Check if we've already skipped and stored this message key
        skipped_key = (remote_public, msg_num)
        if skipped_key in self.state.skipped_keys:
            message_key = self.state.skipped_keys[skipped_key]
            del self.state.skipped_keys[skipped_key]
            return decrypt_message(message_key, ciphertext, associated_data)

        # Check if we need to perform DH ratchet step
        if self.state.dh_remote_public != remote_public:
            self._skip_message_keys(header['prev_count'])
            self._dh_ratchet_step(remote_public)

        # Skip message keys if needed (for out-of-order delivery)
        self._skip_message_keys(msg_num)

        # Derive message key
        if self.state.receiving_chain_key is None:
            raise CryptoError("Receiving chain not initialized")

        self.state.receiving_chain_key, message_key = kdf_chain(
            self.state.receiving_chain_key,
            b"MessageKeys"
        )
        self.state.recv_count += 1

        # Decrypt
        return decrypt_message(message_key, ciphertext, associated_data)

    def _skip_message_keys(self, until: int):
        """
        Skip and store message keys for out-of-order messages.

        Args:
            until: Message number to skip until (exclusive)
        """
        if self.state.receiving_chain_key is None:
            return

        if self.state.recv_count + self.MAX_SKIP < until:
            raise CryptoError(f"Too many skipped messages: {until - self.state.recv_count}")

        while self.state.recv_count < until:
            self.state.receiving_chain_key, message_key = kdf_chain(
                self.state.receiving_chain_key,
                b"MessageKeys"
            )
            # Store skipped key
            key = (self.state.dh_remote_public, self.state.recv_count)
            self.state.skipped_keys[key] = message_key
            self.state.recv_count += 1

    def initialize_receiver(self, initial_message: Dict):
        """
        Initialize as receiver with the first message from sender.

        Args:
            initial_message: First encrypted message containing sender's DH public key
        """
        remote_public = bytes.fromhex(initial_message['header']['dh_public'])
        self._dh_ratchet_step(remote_public)

    def export_state(self) -> str:
        """
        Export ratchet state for persistence.

        Returns:
            JSON string of serialized state
        """
        # Convert bytes to hex for JSON serialization
        state_dict = {
            'root_key': self.state.root_key.hex(),
            'sending_chain_key': self.state.sending_chain_key.hex() if self.state.sending_chain_key else None,
            'receiving_chain_key': self.state.receiving_chain_key.hex() if self.state.receiving_chain_key else None,
            'dh_private': self.state.dh_private.hex() if self.state.dh_private else None,
            'dh_public': self.state.dh_public.hex() if self.state.dh_public else None,
            'dh_remote_public': self.state.dh_remote_public.hex() if self.state.dh_remote_public else None,
            'send_count': self.state.send_count,
            'recv_count': self.state.recv_count,
            'prev_send_count': self.state.prev_send_count,
            'skipped_keys': {
                f"{k[0].hex()}:{k[1]}": v.hex()
                for k, v in self.state.skipped_keys.items()
            }
        }
        return json.dumps(state_dict)

    @classmethod
    def import_state(cls, state_json: str) -> 'DoubleRatchet':
        """
        Import ratchet state from persistence.

        Args:
            state_json: JSON string of serialized state

        Returns:
            DoubleRatchet instance with restored state
        """
        state_dict = json.loads(state_json)

        # Create instance without initialization
        instance = cls.__new__(cls)

        # Parse skipped keys
        skipped_keys = {}
        for key_str, value_hex in state_dict.get('skipped_keys', {}).items():
            pub_hex, num_str = key_str.split(':')
            skipped_keys[(bytes.fromhex(pub_hex), int(num_str))] = bytes.fromhex(value_hex)

        # Restore state
        instance.state = RatchetState(
            root_key=bytes.fromhex(state_dict['root_key']),
            sending_chain_key=bytes.fromhex(state_dict['sending_chain_key']) if state_dict['sending_chain_key'] else None,
            receiving_chain_key=bytes.fromhex(state_dict['receiving_chain_key']) if state_dict['receiving_chain_key'] else None,
            dh_private=bytes.fromhex(state_dict['dh_private']) if state_dict['dh_private'] else None,
            dh_public=bytes.fromhex(state_dict['dh_public']) if state_dict['dh_public'] else None,
            dh_remote_public=bytes.fromhex(state_dict['dh_remote_public']) if state_dict['dh_remote_public'] else None,
            send_count=state_dict['send_count'],
            recv_count=state_dict['recv_count'],
            prev_send_count=state_dict['prev_send_count'],
            skipped_keys=skipped_keys
        )

        return instance
