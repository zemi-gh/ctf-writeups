#!/bin/bash
set -e

echo "======================================================"
echo "  ULTIMATE SKIBIDI CHALLENGE - BUILD SCRIPT"
echo "  Maximum Difficulty | Brain Rot Edition"
echo "======================================================"
echo ""

# Clean
rm -f challenge challenge.packed build/* /tmp/.x19f47e2b8a 2>/dev/null || true

# Compile with maximum obfuscation
echo "[*] Compiling challenge..."
x86_64-linux-gnu-gcc challenge.c -o challenge \
    -O3 \
    -fno-stack-protector \
    -static \
    -s \
    -no-pie \
    -Wl,--strip-all \
    2>&1 | grep -v warning || true

# Strip everything
echo "[*] Stripping symbols..."
x86_64-linux-gnu-strip --strip-all challenge 2>/dev/null || true
x86_64-linux-gnu-strip --remove-section=.note.gnu.build-id challenge 2>/dev/null || true
x86_64-linux-gnu-strip --remove-section=.comment challenge 2>/dev/null || true

# Pack with UPX
echo "[*] Packing with UPX..."
upx --best --ultra-brute challenge -o challenge.packed 2>/dev/null || \
    upx --best challenge -o challenge.packed 2>/dev/null || \
    cp challenge challenge.packed

chmod +x challenge challenge.packed

# Copy to build folder
echo "[*] Copying to build folder..."
cp challenge.packed build/
cp solution.py build/

# Create README for build folder
cat > build/README.md << 'EOF'
# Ultimate SKIBIDI Challenge

## Challenge Files

- `challenge.packed` - The main challenge binary
- `solution.py` - Solution script (for reference)

## Objective

Find the flag path that the malware writes to.

## Flag Format

```
Submit the flag: /tmp/.{path}
```

## Difficulty

⭐⭐⭐⭐⭐ EXTREME

- 4-layer encryption references
- Brain rot obfuscation
- Polymorphic keys
- Anti-debugging
- Time-locked components

## Hints

1. The binary performs a fake "rm -rf" prank
2. Brain rot strings (SKIBIDI, OHIO, GYATT, SIGMA) are encryption keys
3. The path contains "x19f47e2b8a" (six_seven reference)
4. Use strace, Ghidra, IDA Pro, or radare2
5. Or just run it and check /tmp/

Good luck!
EOF

echo ""
echo "======================================================"
echo "  BUILD COMPLETE!"
echo "======================================================"
echo ""
echo "Files created:"
echo "  - challenge (unpacked)"
echo "  - challenge.packed (UPX packed)"
echo "  - build/challenge.packed (for distribution)"
echo "  - build/solution.py (solver)"
echo "  - build/README.md (instructions)"
echo ""
echo "Flag path: /tmp/.x19f47e2b8a"
echo ""
echo "Test with: ./challenge.packed"
echo ""
