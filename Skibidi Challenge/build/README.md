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
