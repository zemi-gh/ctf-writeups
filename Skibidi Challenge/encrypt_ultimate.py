#!/usr/bin/env python3
"""
Ultimate encryption script for NSA challenge
Generates 4-layer encrypted flag path with brain rot keys
"""

import struct
import time

# Constants from C code
SKIBIDI_MAGIC = 0x534B4942
OHIO_CONSTANT = 0x4F48494F
GYATT_PRIME = 0x47594154
SIGMA_SALT = 0x5349474D
SIX_SEVEN_MASK = 0x67

# Encrypted brain rot strings (from C code)
enc_skibidi = bytes([0x12, 0x0A, 0x08, 0x0B, 0x08, 0x05, 0x08, 0x1B,
                     0x1F, 0x0E, 0x08, 0x0F, 0x06, 0x1F])
enc_ohio = bytes([0x0E, 0x07, 0x08, 0x0E, 0x1B, 0x11, 0x08, 0x1D, 0x1D])
enc_gyatt = bytes([0x06, 0x18, 0x00, 0x1F, 0x1F, 0x1B, 0x0C, 0x0E, 0x05, 0x06])
enc_sigma = bytes([0x12, 0x08, 0x06, 0x0C, 0x00, 0x1B, 0x06, 0x11,
                    0x08, 0x0D, 0x05, 0x12, 0x06, 0x1F])

def to_u32(val):
    return val & 0xFFFFFFFF

def derive_skibidi_key(length=32):
    key = bytearray()
    seed = SKIBIDI_MAGIC
    for i in range(length):
        seed = to_u32((seed * 1103515245 + 12345) & 0x7FFFFFFF)
        byte = (seed >> 16) & 0xFF
        byte ^= enc_skibidi[i % len(enc_skibidi)]
        byte ^= SIX_SEVEN_MASK
        key.append(byte & 0xFF)
    return bytes(key)

def derive_ohio_key(length=32):
    key = bytearray()
    seed = OHIO_CONSTANT
    for i in range(length):
        seed = to_u32(seed ^ (seed << 13))
        seed = to_u32(seed ^ (seed >> 17))
        seed = to_u32(seed ^ (seed << 5))
        byte = seed & 0xFF
        byte ^= enc_ohio[i % len(enc_ohio)]
        byte = ((byte << 3) | (byte >> 5)) & 0xFF
        key.append(byte)
    return bytes(key)

def derive_gyatt_key(length=32):
    key = bytearray()
    seed = GYATT_PRIME
    for i in range(length):
        seed = to_u32(seed * 134775813 + 1)
        byte = (seed >> 8) & 0xFF
        byte ^= enc_gyatt[i % len(enc_gyatt)]
        byte = ~byte & 0xFF
        key.append(byte)
    return bytes(key)

def derive_sigma_key(length=32):
    key = bytearray()
    seed = SIGMA_SALT
    # Time component
    t = int(time.time())
    seed = to_u32(seed ^ ((t // 86400) * SIX_SEVEN_MASK))

    for i in range(length):
        seed = to_u32((seed * 69069 + 1) & 0xFFFFFFFF)
        byte = (seed >> 12) & 0xFF
        byte ^= enc_sigma[i % len(enc_sigma)]
        key.append(byte & 0xFF)
    return bytes(key)

def encrypt_layer_alpha(data):
    result = bytearray(data)
    key = derive_skibidi_key(32)
    for i in range(len(result)):
        result[i] = ((result[i] << 3) | (result[i] >> 5)) & 0xFF
        result[i] ^= key[i % len(key)]
    return bytes(result)

def encrypt_layer_beta(data):
    result = bytearray(data)
    key = derive_ohio_key(32)
    for i in range(len(result)):
        result[i] ^= key[i % len(key)]
        result[i] = ((result[i] << 5) | (result[i] >> 3)) & 0xFF
    return bytes(result)

def encrypt_layer_gamma(data):
    result = bytearray(data)
    key = derive_gyatt_key(32)
    for i in range(len(result)):
        result[i] ^= key[i % len(key)]
        result[i] = ~result[i] & 0xFF
    return bytes(result)

def encrypt_layer_delta(data):
    result = bytearray(data)
    key = derive_sigma_key(32)
    for i in range(len(result)):
        result[i] ^= SIX_SEVEN_MASK
        result[i] ^= key[i % len(key)]
    return bytes(result)

def decrypt_layer_alpha(data):
    result = bytearray(data)
    key = derive_skibidi_key(32)
    for i in range(len(result)):
        result[i] ^= key[i % len(key)]
        result[i] = ((result[i] >> 3) | (result[i] << 5)) & 0xFF
    return bytes(result)

def decrypt_layer_beta(data):
    result = bytearray(data)
    key = derive_ohio_key(32)
    for i in range(len(result)):
        result[i] = ((result[i] >> 5) | (result[i] << 3)) & 0xFF
        result[i] ^= key[i % len(key)]
    return bytes(result)

def decrypt_layer_gamma(data):
    result = bytearray(data)
    key = derive_gyatt_key(32)
    for i in range(len(result)):
        result[i] = ~result[i] & 0xFF
        result[i] ^= key[i % len(key)]
    return bytes(result)

def decrypt_layer_delta(data):
    result = bytearray(data)
    key = derive_sigma_key(32)
    for i in range(len(result)):
        result[i] ^= key[i % len(key)]
        result[i] ^= SIX_SEVEN_MASK
    return bytes(result)

def main():
    plaintext = b"/tmp/.x19f47e2b8a"

    print("=" * 70)
    print("  ULTIMATE CHALLENGE - Encryption Script")
    print("=" * 70)
    print()
    print(f"Plaintext: {plaintext.decode()}")
    print()

    # Encrypt through 4 layers
    encrypted = plaintext
    encrypted = encrypt_layer_delta(encrypted)
    encrypted = encrypt_layer_gamma(encrypted)
    encrypted = encrypt_layer_beta(encrypted)
    encrypted = encrypt_layer_alpha(encrypted)

    # XOR with extra layers for maximum obfuscation
    layer_1 = bytearray(encrypted)
    layer_2 = bytearray(len(encrypted))
    layer_3 = bytearray(len(encrypted))

    for i in range(len(encrypted)):
        layer_2[i] = encrypted[i] ^ 0x55
        layer_3[i] = encrypted[i] ^ 0xAA

    print("Encrypted layers (C code):")
    print()
    print("static unsigned char layer_1_enc[] = {")
    print("    " + ", ".join(f"0x{b:02X}" for b in layer_1))
    print("};")
    print()
    print("static unsigned char layer_2_enc[] = {")
    print("    " + ", ".join(f"0x{b:02X}" for b in layer_2))
    print("};")
    print()
    print("static unsigned char layer_3_enc[] = {")
    print("    " + ", ".join(f"0x{b:02X}" for b in layer_3))
    print("};")
    print()

    # Verify decryption
    combined = bytearray(len(encrypted))
    for i in range(len(encrypted)):
        combined[i] = layer_1[i] ^ layer_2[i] ^ layer_3[i]

    decrypted = bytes(combined)
    decrypted = decrypt_layer_alpha(decrypted)
    decrypted = decrypt_layer_beta(decrypted)
    decrypted = decrypt_layer_gamma(decrypted)
    decrypted = decrypt_layer_delta(decrypted)

    print("Verification:")
    try:
        print(f"  Decrypted: {decrypted.decode()}")
        print(f"  Match: {decrypted == plaintext}")
    except:
        print(f"  Decrypted (hex): {decrypted.hex()}")
        print(f"  Expected (hex):  {plaintext.hex()}")
        print(f"  Match: {decrypted == plaintext}")
    print()
    print("=" * 70)

if __name__ == "__main__":
    main()
