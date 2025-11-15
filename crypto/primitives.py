"""
Cryptographic Primitives for End-to-End Encryption

This module provides the foundational cryptographic operations used in the
Signal Protocol-inspired encryption scheme.
"""

import os
import hmac
import hashlib
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoError(Exception):
    """Base exception for cryptographic errors"""
    pass


def generate_dh_keypair() -> Tuple[X25519PrivateKey, X25519PublicKey]:
    """
    Generate a Curve25519 Diffie-Hellman keypair for key exchange.

    Returns:
        Tuple of (private_key, public_key)
    """
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def generate_identity_keypair() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """
    Generate an Ed25519 keypair for digital signatures (identity keys).

    Returns:
        Tuple of (private_key, public_key)
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def dh_exchange(private_key: X25519PrivateKey, public_key: X25519PublicKey) -> bytes:
    """
    Perform Diffie-Hellman key exchange.

    Args:
        private_key: Our private key
        public_key: Their public key

    Returns:
        32-byte shared secret
    """
    return private_key.exchange(public_key)


def kdf_chain(key: bytes, constant: bytes) -> Tuple[bytes, bytes]:
    """
    KDF chain for ratcheting (HKDF-based).

    Args:
        key: Input key material
        constant: Additional info/context

    Returns:
        Tuple of (chain_key, message_key)
    """
    # Derive 64 bytes: 32 for chain key, 32 for message key
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=constant
    )
    output = hkdf.derive(key)
    return output[:32], output[32:]


def kdf_root(root_key: bytes, dh_output: bytes) -> Tuple[bytes, bytes]:
    """
    Root KDF for DH ratchet step.

    Args:
        root_key: Current root key
        dh_output: DH exchange output

    Returns:
        Tuple of (new_root_key, new_chain_key)
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=root_key,
        info=b"DoubleRatchet"
    )
    output = hkdf.derive(dh_output)
    return output[:32], output[32:]


def encrypt_message(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    """
    Encrypt a message using AES-256-GCM.

    Args:
        key: 32-byte encryption key
        plaintext: Message to encrypt
        associated_data: Additional authenticated data

    Returns:
        nonce (12 bytes) + ciphertext + tag (16 bytes)
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext


def decrypt_message(key: bytes, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
    """
    Decrypt a message using AES-256-GCM.

    Args:
        key: 32-byte encryption key
        ciphertext: nonce + encrypted message + tag
        associated_data: Additional authenticated data

    Returns:
        Decrypted plaintext

    Raises:
        CryptoError: If decryption fails
    """
    if len(ciphertext) < 28:  # 12 bytes nonce + 16 bytes tag minimum
        raise CryptoError("Ciphertext too short")

    nonce = ciphertext[:12]
    actual_ciphertext = ciphertext[12:]

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, actual_ciphertext, associated_data)
        return plaintext
    except Exception as e:
        raise CryptoError(f"Decryption failed: {str(e)}")


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """
    Compute HMAC-SHA256.

    Args:
        key: HMAC key
        data: Data to authenticate

    Returns:
        32-byte HMAC tag
    """
    return hmac.new(key, data, hashlib.sha256).digest()


def serialize_public_key(public_key: X25519PublicKey) -> bytes:
    """Serialize X25519 public key to bytes"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )


def deserialize_public_key(key_bytes: bytes) -> X25519PublicKey:
    """Deserialize bytes to X25519 public key"""
    return X25519PublicKey.from_public_bytes(key_bytes)


def serialize_identity_public_key(public_key: Ed25519PublicKey) -> bytes:
    """Serialize Ed25519 public key to bytes"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )


def deserialize_identity_public_key(key_bytes: bytes) -> Ed25519PublicKey:
    """Deserialize bytes to Ed25519 public key"""
    return Ed25519PublicKey.from_public_bytes(key_bytes)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison to prevent timing attacks.

    Args:
        a: First byte string
        b: Second byte string

    Returns:
        True if equal, False otherwise
    """
    return hmac.compare_digest(a, b)
