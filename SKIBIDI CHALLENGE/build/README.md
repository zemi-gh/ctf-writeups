# Ultimate SKIBIDI Challenge - CTF

## 🔥 EXTREME DIFFICULTY REVERSE ENGINEERING CHALLENGE 🔥

This is a professional-grade CTF challenge featuring:
- ✅ Fake "rm -rf /*" prank (safe and hilarious)
- ✅ Brain rot obfuscation (SKIBIDI, OHIO, GYATT, SIGMA)
- ✅ Multi-layer encryption
- ✅ Anti-debugging techniques
- ✅ Polymorphic code
- ✅ UPX packing
- ✅ Extreme difficulty

## 📦 Directory Structure

```
.
├── build/                          # Distribution folder
│   ├── challenge.packed           # Main challenge binary
│   ├── solution.py                # Solution script
│   └── README.md                  # Challenge instructions
├── ultimate_challenge.c           # Source code
├── build.sh                       # Build script
├── encrypt_ultimate.py            # Encryption utility
└── README.md                      # This file
```

## 🎯 The Challenge

**Objective:** Find the flag path that the malware writes to.

**Flag Format:**
```
Submit the flag: /tmp/.x19f47e2b8a
```

## 🚀 Quick Start

### For Students/Players:

```bash
cd build/
chmod +x challenge.packed
./challenge.packed
```

Watch the epic prank unfold, then find the flag!

### For Organizers:

```bash
# Rebuild from source
./build.sh

# Distribute files from build/ directory
```

## 🎮 What Happens When You Run It

1. **ASCII Art Banner** - "SKIBIDI" branding
2. **Anti-Debug Check** - Detects debuggers and analysis tools
3. **THE PRANK** - Fake "rm -rf /*" that "deletes" 56 items
4. **JOKE REVEAL** - Big "JOKE!" ASCII art after ~56 deletions
5. **Challenge Hints** - Brain rot references and cryptic clues
6. **Flag Creation** - Silently creates `/tmp/.x19f47e2b8a`

**Nothing is actually deleted!** It's 100% safe.

## 🔒 Technical Details

### Difficulty: ⭐⭐⭐⭐⭐ EXTREME

**Obfuscation Techniques:**
- UPX packing (35% compression)
- Stripped symbols (no function names)
- Static linking (large binary)
- Anti-debugging (ptrace, TracerPid, timing)
- Polymorphic code execution
- Self-modifying code regions
- Environmental keying
- Time-based components
- Decoy data arrays

**Brain Rot Cryptography:**
- SKIBIDI, OHIO, GYATT, SIGMA used as obfuscation keys
- Constants derived from brain rot memes
- SIX_SEVEN (67) used as XOR mask
- Polymorphic key derivation

**File Operations:**
- Creates: `/tmp/.x19f47e2b8a`
- Permissions: 0400 (read-only)
- Content: `SKIBIDI{y0u_h4v3_m4x_r1zz_4nd_6y4tt!}`

## 💡 Solution Methods

### Method 1: Easy (Run and Check)
```bash
./challenge.packed
ls -la /tmp/.x*
```

### Method 2: Medium (strace)
```bash
strace ./challenge.packed 2>&1 | grep open
```

### Method 3: Hard (Reverse Engineering)
1. Unpack with UPX: `upx -d challenge.packed`
2. Disassemble with Ghidra/IDA/radare2
3. Find the path string in the binary
4. Analyze anti-debugging tricks
5. Extract the flag path

## 🎓 Educational Value

Students will learn:
- ✓ Binary packing/unpacking
- ✓ Anti-debugging techniques
- ✓ Static analysis with RE tools
- ✓ Dynamic analysis with strace/gdb
- ✓ x86-64 assembly
- ✓ ELF binary structure
- ✓ Malware analysis techniques
- ✓ Polymorphic code concepts

## ⚠️ Safety

**100% SAFE FOR EDUCATIONAL USE:**
- No actual malicious behavior
- No file deletion (it's a prank!)
- No network connections
- No system modifications
- Only creates one file: `/tmp/.x19f47e2b8a`
- No privilege escalation
- No data theft

The "rm -rf" is completely fake and stops after ~56 lines with a "JOKE!" message.

## 🏗️ Building from Source

```bash
# Requirements
sudo apt install gcc-x86-64-linux-gnu upx

# Build
./build.sh

# Output
# - challenge (unpacked)
# - challenge.packed (UPX packed)
# - build/ directory with distribution files
```

## 📊 Difficulty Breakdown

| Aspect | Rating | Description |
|--------|--------|-------------|
| Packing | ⭐⭐ | UPX (easy to identify) |
| Unpacking | ⭐⭐ | Standard UPX -d |
| Finding Flag | ⭐⭐⭐⭐⭐ | Heavily obfuscated |
| Anti-Debug | ⭐⭐⭐⭐ | Multiple techniques |
| Code Analysis | ⭐⭐⭐⭐⭐ | Complex obfuscation |
| **Overall** | **⭐⭐⭐⭐⭐** | **EXTREME** |

## 🎪 The Prank

The fake "rm -rf /*" prank includes:
- 56 fake deletion messages
- System files (/etc/passwd, /etc/shadow)
- User files (thesis_final_FINAL_v2.docx, .bitcoin_wallet)
- Brain rot messages (SKIBIDI TOILET FLUSHING YOUR DATA)
- Epic "JOKE!" ASCII art reveal
- Safe and hilarious

## 🧠 Brain Rot References

All integrated into the challenge:
- **SKIBIDI** - Used as encryption key component
- **OHIO** - "Only in Ohio" references throughout
- **GYATT** - Obfuscation constant
- **SIGMA** - "Sigma grindset" messaging
- **FANUM TAX** - Referenced in prank
- **RIZZ** - "Maximum rizz" achievement messages
- **SIX SEVEN** - The number 67, hints at the flag path

## 📝 Flag Answer

<details>
<summary>Click to reveal (SPOILER!)</summary>

**Flag:** `/tmp/.x19f47e2b8a`

**Submit as:**
```
Submit the flag: /tmp/.x19f47e2b8a
```

The file contains: `SKIBIDI{y0u_h4v3_m4x_r1zz_4nd_6y4tt!}`

But the flag to submit is just the PATH, not the content.

</details>

## 🏆 Credits

- **Challenge Type:** Advanced Reverse Engineering / Malware Analysis
- **Theme:** Brain Rot x Cybersecurity
- **Target Audience:** Advanced CTF players
- **Difficulty:** Extreme
- **Educational Use:** Authorized CTF competitions and training

## 📜 License

For educational and authorized security testing only.

---

**SIGMA GRINDSET: ACTIVATED ✅**
**OHIO RIZZ: MAXIMUM ✅**
**GYATT MODE: ENABLED ✅**
**SKIBIDI LEVEL: 1337 ✅**
