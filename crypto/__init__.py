"""
Cryptographic module for end-to-end encrypted chat.

Implements Signal Protocol-inspired encryption with:
- X3DH (Extended Triple Diffie-Hellman) key agreement
- Double Ratchet algorithm for forward secrecy
"""

from .primitives import (
    generate_dh_keypair,
    generate_identity_keypair,
    dh_exchange,
    encrypt_message,
    decrypt_message,
    CryptoError
)

__all__ = [
    'generate_dh_keypair',
    'generate_identity_keypair',
    'dh_exchange',
    'encrypt_message',
    'decrypt_message',
    'CryptoError'
]
