#!/usr/bin/env python3
"""
Helper script to encrypt strings for the CTF challenge
Uses multiple XOR layers for maximum obfuscation
"""

def xor_encrypt(data, key):
    """Single XOR encryption layer"""
    result = bytearray()
    for i, byte in enumerate(data):
        result.append(byte ^ key[i % len(key)])
    return bytes(result)

def multi_layer_encrypt(plaintext, keys):
    """Apply multiple XOR encryption layers"""
    result = plaintext.encode() if isinstance(plaintext, str) else plaintext
    for key in keys:
        result = xor_encrypt(result, key)
    return result

def format_for_c(data):
    """Format encrypted data for C array"""
    hex_values = [f"0x{b:02X}" for b in data]
    return ", ".join(hex_values)

# Keys (matching the C code)
key1 = b"Skibidi"  # 0x53, 0x6B, 0x69, 0x62, 0x69, 0x64, 0x69
key2 = b"OhioRizz"  # 0x4F, 0x68, 0x69, 0x6F, 0x52, 0x69, 0x7A, 0x7A
key3 = b"Gyatt"     # 0x47, 0x79, 0x61, 0x74, 0x74

# The flag path
flag_path = "/tmp/.six_seven"

# Encrypt the flag path with all three layers
encrypted = multi_layer_encrypt(flag_path, [key3, key2, key1])

print("=== FLAG PATH ENCRYPTION ===")
print(f"Plaintext: {flag_path}")
print(f"Encrypted (C array format):")
print(f"    {format_for_c(encrypted)}")
print()

# Encrypt brain rot strings
brain_rot_strings = [
    "SKIBIDI TOILET",
    "SIGMA GRINDSET",
    "GYATT MODE"
]

obfuscation_key = 0x42 ^ 0x69  # SKIBIDI_TOILET ^ OHIO_RIZZ

print("=== BRAIN ROT STRINGS ===")
for s in brain_rot_strings:
    encrypted = bytes([b ^ obfuscation_key for b in s.encode()])
    print(f"{s}:")
    print(f"    {format_for_c(encrypted)}")
print()

# Stage 2 flag content encryption
flag_content = "SKIBIDI{y0u_f0und_th3_s1x_s3v3n_h1dd3n_fl4g!}"
stage2_encrypted = bytearray()

for i, c in enumerate(flag_content):
    b = ord(c)
    b ^= 0x67  # six * seven with offset
    b ^= (i % 7)
    b ^= 0xAA ^ 0x55  # OBFUSCATE_1
    stage2_encrypted.append(b)

print("=== STAGE 2 FLAG CONTENT ===")
print(f"Content: {flag_content}")
print(f"Encrypted (C array format):")
print(f"    {format_for_c(stage2_encrypted)}")
print()

# Generate some fake encrypted strings for red herrings
red_herrings = [
    "/tmp/flag.txt",
    "/home/skibidi",
    "/var/rizz/flag"
]

print("=== RED HERRINGS ===")
for rh in red_herrings:
    simple_enc = bytes([ord(c) for c in rh])  # Just convert to hex
    print(f"{rh}:")
    print(f"    {format_for_c(simple_enc)}")
print()

# Calculate verification hash
import hashlib
verification = hashlib.sha256(flag_path.encode()).hexdigest()
print("=== VERIFICATION ===")
print(f"SHA256 of flag path: {verification}")
print(f"Flag to submit: {flag_path}")
print()

print("=== HINTS FOR PLAYERS ===")
print("1. The binary contains multiple layers of XOR encryption")
print("2. Keys are: 'Skibidi', 'OhioRizz', 'Gyatt'")
print("3. The flag is a file path, not the file contents")
print("4. Look for encrypted_flag[] array in the binary")
print("5. The fake rm -rf is just a prank!")
print("6. Use strings, objdump, gdb, radare2, or ghidra to analyze")
