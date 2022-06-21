from pwn import *
import sys
import re

def pause():
   log.progress("Press any key to continue ...")
   sys.stdin.read(1)

io = process("ncat --ssl 9e3a09c20a0ee46b9872473a-secureboot.challenge.master.cscg.live 31337", shell=True)
io.recvuntil(b"bootloader: (default: 0)\n")
io.sendline(b"0")

with open("2rev_dump_flag.bin", "rb") as fin:
    img = fin.read().hex()

SBOX = bytes.fromhex("fabc007cbe007cbf0006b98000fcf366a566ea190600000000fbb80202bb007cb281b90100b600cd13bf007c8d36640789f88d3e6c07b90200f366a589c783ee0866e85500000089fb8d3e6c07b908008a248a0530e088044647e2f489df83ee0883c70889f82d007e75c5be007e8d3eed0666e84a000000be007e8d3e6407b90800f3a67505b8007cffe08d360007b40eac3c000f848c00cd10ebf5b90001ac4e31d2565701d78a2500e0bb0006d74283e20701d68a2400e0d0c088045f5ee2e2c3b900015689ca4a83e207678a2416678a0417d501bb0006d74283e2076601d68a24d0cc28c488245ee2d9c341004100410041000000000000000000000000")

buf = list(bytes.fromhex("99ae4fd02538b4d4"))
key = list(bytes.fromhex("4100410041004100"))

"""
# encrypt:
for i in range(0x100):
    i = 0x100 - i
    x = buf[i % 8]
    buf[i % 8] = (((x >> 1 | x << 7) & 0xFF) - SBOX[ (key[(i - 1) % 8] + buf[(i - 1) % 8]) & 0xFF ]) & 0xFF

print(bytes(buf).hex())
"""

# decrypt:
for i in range(0x100):
    i = i + 1
    x = (buf[i % 8] + SBOX[ (key[(i - 1) % 8] + buf[(i - 1) % 8]) & 0xFF ]) & 0xFF
    buf[i % 8] = ((x << 1 | x >> 7) & 0xFF)

sig = bytes(buf).hex()
print(sig) # = 4b5f97aba7c20192

io.send((img + sig).encode())
io.send(b"EOF")

def strip_ansi_b(s: bytes):
    # 7-bit and 8-bit C1 ANSI sequences
    ansi_escape_8bit = re.compile(br'''
        (?: # either 7-bit C1, two bytes, ESC Fe (omitting CSI)
            \x1B
            [@-Z\\-_]
        |   # or a single 8-bit byte Fe (omitting CSI)
            [\x80-\x9A\x9C-\x9F]
        |   # or CSI + control codes
            (?: # 7-bit CSI, ESC [
                \x1B\[
            |   # 8-bit CSI, 9B
                \x9B
            )
            [0-?]*  # Parameter bytes
            [ -/]*  # Intermediate bytes
            [@-~]   # Final byte
        )
    ''', re.VERBOSE)
    return ansi_escape_8bit.sub(b'', s)


def recvall(io):
    buf = b""
    for _ in range(1000):
        try:
            recv = io.recv(1024, timeout=0.5)
            if not recv:
                break
        except:
            break
        buf += recv
    return buf

buf = recvall(io)
with open("2rev_out.txt", "w") as fout:
    print(repr(buf), file=fout)
    print("-----------------", file=fout)
    print(repr(strip_ansi_b(buf)), file=fout)

io.close()
