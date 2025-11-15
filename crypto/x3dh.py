"""
X3DH (Extended Triple Diffie-Hellman) Key Agreement Protocol

This module implements a simplified version of the X3DH protocol used in Signal.
It establishes a shared secret between two parties who have not communicated before.
"""

import os
from typing import Dict, Tuple, Optional
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .primitives import (
    generate_dh_keypair,
    generate_identity_keypair,
    dh_exchange,
    kdf_root,
    serialize_public_key,
    deserialize_public_key,
    serialize_identity_public_key,
    deserialize_identity_public_key,
)


@dataclass
class PreKeyBundle:
    """
    Public key bundle uploaded to the server for key exchange.

    Attributes:
        identity_key: Long-term Ed25519 identity public key
        signed_pre_key: Medium-term X25519 public key
        one_time_pre_key: Single-use X25519 public key (optional)
    """
    identity_key: bytes
    signed_pre_key: bytes
    one_time_pre_key: Optional[bytes] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            'identity_key': self.identity_key.hex(),
            'signed_pre_key': self.signed_pre_key.hex(),
            'one_time_pre_key': self.one_time_pre_key.hex() if self.one_time_pre_key else None
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'PreKeyBundle':
        """Create from dictionary"""
        return cls(
            identity_key=bytes.fromhex(data['identity_key']),
            signed_pre_key=bytes.fromhex(data['signed_pre_key']),
            one_time_pre_key=bytes.fromhex(data['one_time_pre_key']) if data.get('one_time_pre_key') else None
        )


@dataclass
class X3DHResult:
    """
    Result of X3DH key agreement.

    Attributes:
        shared_key: The derived shared secret (32 bytes)
        associated_data: Data to be used as additional authenticated data
        ephemeral_public: Our ephemeral public key to send to the recipient
    """
    shared_key: bytes
    associated_data: bytes
    ephemeral_public: bytes


class X3DHKeyExchange:
    """
    Handles X3DH key agreement for establishing initial shared secrets.
    """

    def __init__(self):
        """Initialize X3DH key exchange handler"""
        self.identity_private: Optional[Ed25519PrivateKey] = None
        self.identity_public: Optional[Ed25519PublicKey] = None
        self.signed_pre_key_private: Optional[X25519PrivateKey] = None
        self.signed_pre_key_public: Optional[X25519PublicKey] = None
        self.one_time_pre_keys: Dict[bytes, X25519PrivateKey] = {}

    def generate_identity_keys(self) -> bytes:
        """
        Generate long-term identity keypair.

        Returns:
            Public identity key (32 bytes)
        """
        self.identity_private, self.identity_public = generate_identity_keypair()
        return serialize_identity_public_key(self.identity_public)

    def generate_prekeys(self, num_one_time_keys: int = 10) -> PreKeyBundle:
        """
        Generate prekey bundle for upload to server.

        Args:
            num_one_time_keys: Number of one-time prekeys to generate

        Returns:
            PreKeyBundle containing public keys
        """
        if not self.identity_public:
            raise ValueError("Identity keys must be generated first")

        # Generate signed prekey
        self.signed_pre_key_private, self.signed_pre_key_public = generate_dh_keypair()

        # Generate one-time prekeys
        for _ in range(num_one_time_keys):
            private, public = generate_dh_keypair()
            public_bytes = serialize_public_key(public)
            self.one_time_pre_keys[public_bytes] = private

        # Return first one-time prekey in bundle
        one_time_public = next(iter(self.one_time_pre_keys.keys())) if self.one_time_pre_keys else None

        return PreKeyBundle(
            identity_key=serialize_identity_public_key(self.identity_public),
            signed_pre_key=serialize_public_key(self.signed_pre_key_public),
            one_time_pre_key=one_time_public
        )

    def initiate_session(self, recipient_bundle: PreKeyBundle, our_identity_private: Ed25519PrivateKey) -> X3DHResult:
        """
        Initiate a session by performing X3DH with recipient's prekey bundle.

        This is called by the sender to establish the initial shared secret.

        Args:
            recipient_bundle: Recipient's public key bundle
            our_identity_private: Our identity private key (converted to X25519 for DH)

        Returns:
            X3DHResult containing shared key and associated data
        """
        # Generate ephemeral keypair
        ephemeral_private, ephemeral_public = generate_dh_keypair()

        # Deserialize recipient's public keys
        recipient_identity = deserialize_identity_public_key(recipient_bundle.identity_key)
        recipient_signed_pre = deserialize_public_key(recipient_bundle.signed_pre_key)
        recipient_one_time = deserialize_public_key(recipient_bundle.one_time_pre_key) if recipient_bundle.one_time_pre_key else None

        # For simplicity, we'll use our ephemeral key for DH operations
        # In real Signal, identity keys would also participate in some DH operations

        # Perform DH operations:
        # DH1 = DH(ephemeral, signed_pre_key)
        dh1 = dh_exchange(ephemeral_private, recipient_signed_pre)

        # DH2 = DH(ephemeral, one_time_pre_key) if available
        dh2 = dh_exchange(ephemeral_private, recipient_one_time) if recipient_one_time else b'\x00' * 32

        # Concatenate DH outputs
        dh_concat = dh1 + dh2

        # Derive shared secret using KDF
        # In real X3DH, this would use HKDF with more complex info string
        shared_key, _ = kdf_root(b'\x00' * 32, dh_concat)

        # Create associated data
        associated_data = recipient_bundle.identity_key + serialize_public_key(ephemeral_public)

        return X3DHResult(
            shared_key=shared_key,
            associated_data=associated_data,
            ephemeral_public=serialize_public_key(ephemeral_public)
        )

    def complete_session(self, ephemeral_public_bytes: bytes, one_time_key_public: Optional[bytes]) -> bytes:
        """
        Complete a session by computing shared secret from received ephemeral key.

        This is called by the recipient to derive the same shared secret.

        Args:
            ephemeral_public_bytes: Sender's ephemeral public key
            one_time_key_public: The one-time prekey that was used (if any)

        Returns:
            Shared secret (32 bytes)
        """
        if not self.signed_pre_key_private:
            raise ValueError("Prekeys must be generated first")

        ephemeral_public = deserialize_public_key(ephemeral_public_bytes)

        # DH1 = DH(signed_pre_key, ephemeral)
        dh1 = dh_exchange(self.signed_pre_key_private, ephemeral_public)

        # DH2 = DH(one_time_pre_key, ephemeral) if available
        dh2 = b'\x00' * 32
        if one_time_key_public and one_time_key_public in self.one_time_pre_keys:
            one_time_private = self.one_time_pre_keys[one_time_key_public]
            dh2 = dh_exchange(one_time_private, ephemeral_public)
            # Delete used one-time key
            del self.one_time_pre_keys[one_time_key_public]

        # Concatenate DH outputs
        dh_concat = dh1 + dh2

        # Derive shared secret
        shared_key, _ = kdf_root(b'\x00' * 32, dh_concat)

        return shared_key

    def get_one_time_prekey(self) -> Optional[bytes]:
        """
        Get a one-time prekey for key exchange.

        Returns:
            Public key bytes, or None if no keys available
        """
        if not self.one_time_pre_keys:
            return None
        return next(iter(self.one_time_pre_keys.keys()))
