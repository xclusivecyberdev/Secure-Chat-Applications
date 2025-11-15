#!/usr/bin/env python3
"""
Simple tests for cryptographic primitives.
This is a basic sanity check - not comprehensive unit tests.
"""

import sys
from crypto.primitives import (
    generate_dh_keypair,
    generate_identity_keypair,
    dh_exchange,
    encrypt_message,
    decrypt_message,
    kdf_chain,
    kdf_root,
    CryptoError
)
from crypto.x3dh import X3DHKeyExchange, PreKeyBundle
from crypto.double_ratchet import DoubleRatchet


def test_dh_exchange():
    """Test Diffie-Hellman key exchange"""
    print("Testing DH exchange...")

    # Alice generates keypair
    alice_private, alice_public = generate_dh_keypair()

    # Bob generates keypair
    bob_private, bob_public = generate_dh_keypair()

    # Both compute shared secret
    alice_shared = dh_exchange(alice_private, bob_public)
    bob_shared = dh_exchange(bob_private, alice_public)

    # Shared secrets should match
    assert alice_shared == bob_shared, "DH exchange failed"
    assert len(alice_shared) == 32, "Wrong shared secret length"

    print("✓ DH exchange works")


def test_encryption():
    """Test symmetric encryption"""
    print("Testing encryption...")

    key = b"0" * 32  # 32-byte key
    plaintext = b"Hello, World!"

    ciphertext = encrypt_message(key, plaintext)
    decrypted = decrypt_message(key, ciphertext)

    assert decrypted == plaintext, "Decryption failed"
    assert ciphertext != plaintext, "Ciphertext equals plaintext"

    # Test authentication
    try:
        wrong_key = b"1" * 32
        decrypt_message(wrong_key, ciphertext)
        assert False, "Should have raised CryptoError"
    except CryptoError:
        pass  # Expected

    print("✓ Encryption/decryption works")


def test_kdf():
    """Test key derivation functions"""
    print("Testing KDF...")

    key = b"initial_key_material_32bytes"

    # Test chain KDF
    chain_key, message_key = kdf_chain(key, b"test")
    assert len(chain_key) == 32, "Wrong chain key length"
    assert len(message_key) == 32, "Wrong message key length"
    assert chain_key != message_key, "Keys should be different"

    # Test root KDF
    dh_output = b"dh_output_32_bytes_long_test"
    root_key, chain_key2 = kdf_root(b"0" * 32, dh_output)
    assert len(root_key) == 32, "Wrong root key length"
    assert len(chain_key2) == 32, "Wrong chain key length"

    print("✓ KDF works")


def test_x3dh():
    """Test X3DH key exchange"""
    print("Testing X3DH...")

    # Alice (initiator)
    alice = X3DHKeyExchange()
    alice.generate_identity_keys()

    # Bob (receiver)
    bob = X3DHKeyExchange()
    bob.generate_identity_keys()
    bob_bundle = bob.generate_prekeys(num_one_time_keys=5)

    # Alice initiates session
    result = alice.initiate_session(bob_bundle, alice.identity_private)

    assert len(result.shared_key) == 32, "Wrong shared key length"
    assert result.ephemeral_public is not None, "No ephemeral key"

    # Bob completes session
    bob_shared = bob.complete_session(
        result.ephemeral_public,
        bob_bundle.one_time_pre_key
    )

    # Both should have same shared secret
    assert result.shared_key == bob_shared, "X3DH shared secrets don't match"

    print("✓ X3DH works")


def test_double_ratchet():
    """Test Double Ratchet algorithm"""
    print("Testing Double Ratchet...")

    # Shared secret from X3DH
    shared_secret = b"shared_secret_from_x3dh_test"

    # Alice (sender)
    alice_ratchet = DoubleRatchet(shared_secret, sending=True)

    # Bob (receiver)
    bob_ratchet = DoubleRatchet(shared_secret, sending=False)

    # Alice sends first message
    plaintext1 = b"Hello Bob!"
    encrypted1 = alice_ratchet.encrypt(plaintext1)

    # Bob initializes and decrypts
    bob_ratchet.initialize_receiver(encrypted1)
    decrypted1 = bob_ratchet.decrypt(encrypted1)
    assert decrypted1 == plaintext1, "First message decryption failed"

    # Bob sends reply
    plaintext2 = b"Hi Alice!"
    encrypted2 = bob_ratchet.encrypt(plaintext2)
    decrypted2 = alice_ratchet.decrypt(encrypted2)
    assert decrypted2 == plaintext2, "Reply decryption failed"

    # Alice sends another message
    plaintext3 = b"How are you?"
    encrypted3 = alice_ratchet.encrypt(plaintext3)
    decrypted3 = bob_ratchet.decrypt(encrypted3)
    assert decrypted3 == plaintext3, "Second message decryption failed"

    print("✓ Double Ratchet works")


def test_state_export_import():
    """Test ratchet state serialization"""
    print("Testing state export/import...")

    shared_secret = b"test_secret_32_bytes_long!!"

    # Create ratchet and send message
    ratchet1 = DoubleRatchet(shared_secret, sending=True)
    msg1 = ratchet1.encrypt(b"test message")

    # Export state
    state_json = ratchet1.export_state()

    # Import state
    ratchet2 = DoubleRatchet.import_state(state_json)

    # Should be able to encrypt with restored state
    msg2 = ratchet2.encrypt(b"another message")

    assert msg1 != msg2, "Messages should be different"

    print("✓ State export/import works")


def run_all_tests():
    """Run all tests"""
    print("\n" + "="*50)
    print("Running Cryptographic Tests")
    print("="*50 + "\n")

    try:
        test_dh_exchange()
        test_encryption()
        test_kdf()
        test_x3dh()
        test_double_ratchet()
        test_state_export_import()

        print("\n" + "="*50)
        print("✓ All tests passed!")
        print("="*50 + "\n")
        return 0

    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
