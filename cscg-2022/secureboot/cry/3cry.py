from pwn import *
import sys
import secrets
import functools
import re

def pause():
   log.progress("Press any key to continue ...")
   sys.stdin.read(1)


payload = bytes.fromhex("""
9c 31 2d 5a 4e fa 10 8c
53 60 8c 64 7b 4a 8d 21
a9 f8 36 77 31 5a 1b 9c
e9 26 ea 6b f4 0e 4f 89
94 64 d0 a8 41 f5 59 2c
7e 4a 60 7a f8 63 30 10
3d c9 23 8c dc 8b f4 e9
73 71 33 f5 9b 5e d4 ed
ef 9a 53 fb 7b 1c e2 21
e1 e9 92 6e e2 e1 b0 6a
b5 70 c4 e7 b3 78 40 f2
f3 4f ed 0f f0 32 36 f5
82 a8 ed 0d f9 27 13 85
17 3b 76 8c e4 8a 74 ad
22 e2 72 04 b3 8a c0 f5
61 bb f2 e6 b7 76 35 63
a3 a5 96 af 2c e9 8c a5
61 8e 53 05 c4 26 9e 74
5f 39 65 fa 46 e0 7e 62
1c ae cb 28 45 a9 61 e2
f2 bb 56 21 a2 c1 da 23
33 c5 9c ad 68 93 8e b2
a4 c2 95 a7 2d c0 0b 0a
72 d4 91 c5 f1 7c bd 8b
0b 7c 3b fb 2b 0a 5e 7e
c8 62 0a 36 d5 44 1f b4
08 d3 f1 6d 47 28 62 22
f1 c0 ca d9 99 6c fd 27
9c 31 52 36 0c 01 89 a2
78 58 1a e6 4d 67 5c a7
f7 50 65 1c 3f d8 3a c4
58 c5 a0 01 78 98 e0 93
fa d1 71 9b 04 fb e0 1f
f4 c9 ef 28 60 70 09 3e
08 77 bc 0e f3 25 23 0b
3a 84 2e a8 ae c4 02 3f
64 a1 24 38 66 09 06 80
90 7e f9 46 2b 7a 96 36
72 65 ee a2 3a 6a cf 69
fe 5b b1 da 42 f2 c2 c7
56 69 05 d2 8e 51 b8 28
27 6f f9 31 b2 8f 1d 03
41 f8 96 9e 1d 78 71 2f
7b 2c 76 84 d1 af 61 c9
76 ae b1 ac b9 ad ae bb
f4 4a e4 07 77 4d b8 4e
74 e3 fc ac 19 a1 bf eb
e5 38 dc df c1 b4 32 93
56 a1 2a 03 83 21 96 07
a1 46 44 12 2b cc 20 34
f5 5b a0 a6 65 b0 47 29
8b c1 58 85 b1 d1 44 28
7c 6b 53 a3 ea ad 02 0b
f5 8d fd ad 29 03 41 b7
f9 9f f0 e9 6d d3 1f 4c
fd 1f a4 61 2e 73 d1 68
01 e5 ec 54 0c 63 d8 06
77 e6 d2 a5 f0 8c 60 1d
61 35 cb 71 9d cd 30 6d
c4 9a 92 17 db 3d 39 c1
f3 2f 08 c2 f2 04 f0 8a
63 fc 9d e7 1e e6 cf 29
2b 3d 2e 65 7c 7e 98 fc
5f dc 02 da e9 21 08 2e
""")

KEY_PAYLOADS = [
    bytes.fromhex("14 77 cb 43 0c 3a 57 f2"),
    bytes.fromhex("ce 77 9a 3a a9 b0 40 b8"),
    bytes.fromhex("89 be 4e f8 a2 31 5b a0"),
    bytes.fromhex("bc d7 62 17 6b 1d b1 3b"),
    bytes.fromhex("67 c7 77 e2 3b fe 47 3a"),
    bytes.fromhex("49 e5 79 c2 09 f3 11 b1"),
    bytes.fromhex("bd e1 3a a6 76 f1 3d 70"),
    bytes.fromhex("c1 2c 0a 62 70 d2 e0 c7"),
]

SBOX = list(bytes.fromhex("fabc007cbe007cbf0006b98000fcf366a566ea190600000000fbb80202bb007cb281b90100b600cd13bf007c8d36640789f88d3e6c07b90200f366a589c783ee0866e85500000089fb8d3e6c07b908008a248a0530e088044647e2f489df83ee0883c70889f82d007e75c5be007e8d3eed0666e84a000000be007e8d3e6407b90800f3a67505b8007cffe08d360007b40eac3c000f848c00cd10ebf5b90001ac4e31d2565701d78a2500e0bb0006d74283e20701d68a2400e0d0c088045f5ee2e2c3b900015689ca4a83e207678a2416678a0417d501bb0006d74283e2076601d68a24d0cc28c488245ee2d9c341004100410041000000000000000000000000"))

def encrypt(buf: list, key: list):
    # encrypt:
    for i in range(0x100):
        i = 0x100 - i
        x = buf[i % 8]
        buf[i % 8] = (((x >> 1 | x << 7) & 0xFF) - SBOX[ (key[(i - 1) % 8] + buf[(i - 1) % 8]) & 0xFF ]) & 0xFF


def decrypt(buf: list, key: list):
    # decrypt:
    sboxIndices = set()
    for i in range(0x100):
        i = i + 1
        j =  (key[(i - 1) % 8] + buf[(i - 1) % 8]) & 0xFF
        sboxIndices.add(j)
        x = (buf[i % 8] + SBOX[j]) & 0xFF
        buf[i % 8] = ((x << 1 | x >> 7) & 0xFF)
    return sboxIndices


def calc_hash(inp):
    sboxIndices = set()
    buf = [0] * 8
    for i in range(0, 512, 8):
        key = inp[i:i+8]

        tmpBuf = buf.copy()
        sboxIndices.update(decrypt(tmpBuf, key))
        buf = [ a ^ b for a, b in zip(buf, tmpBuf) ]

    return buf, sboxIndices

def find_key_leak(idx):
    base = list(payload)

    idx += 237

    badKeyIndices = {0 + 237, 1 + 237, 2 + 237, 3 + 237, 4 + 237, 5 + 237, 6 + 237, 7 + 237}

    while True:
        base[-8:] = list(secrets.token_bytes(8))

        _, indices = calc_hash(base)
        if frozenset(badKeyIndices.intersection(indices)) == frozenset({idx}):
            break

    return base


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
            recv = io.recv(4096, timeout=1)
            if not recv:
                break
        except:
            break
        buf += recv
    return buf

prod_key = []

def start_con():
    io = process("ncat --ssl 58e0d5b1b0ede1a21b4fd23a-secureboot.challenge.master.cscg.live 31337", shell=True)
    io.recvuntil(b"bootloader: (default: 0)\n")
    io.sendline(b"1")
    buf = recvall(io)
    return io

for keyIdx in range(8):
    print(keyIdx)

    kb = 0
    while kb < 256:
        SBOX[237 + keyIdx] = kb


        img = find_key_leak(keyIdx)
        """
        img = list(payload)
        img[-8:] = list(KEY_PAYLOADS[keyIdx])
        """
        img.extend([0] * 8) # dummy signature

        assert len(img) == 520

        io = start_con()
        io.send(bytes(img).hex().encode())
        io.sendline(b"EOF")

        buf = recvall(io)

        buf = strip_ansi_b(buf)
        io.close()

        try:
            target = buf.index(b"Invalid signature!")
            target = bytes.fromhex(buf[target + 18:target+18 + 16].decode())
        except ValueError as e:
            print(repr(e))
            print(repr(buf))
            continue

        assert len(target) == 8

        print(hex(kb), "target is", target.hex())
        if calc_hash(img)[0] == list(target):
            print(f"Found keybyte {keyIdx}:", hex(kb))
            prod_key.append(kb)
            break

        kb += 1
    else:
        print("Missed key byte!")
        exit(1)


with open("2rev_dump_flag.bin", "rb") as fout:
    img = fout.read()

buf = [0] * 8
for i in range(0, len(img), 8):
    key = img[i:i+8]

    tmpBuf = buf.copy()
    decrypt(tmpBuf, key)
    buf = [ a ^ b for a, b in zip(buf, tmpBuf) ]

decrypt(buf, prod_key)

img_signed = img + bytes(buf)
io = start_con()

io.send(bytes(img_signed).hex().encode())
io.send(b"EOF")

buf = recvall(io)

buf = strip_ansi_b(buf)
with open(f"3cry_out.txt", "w") as fout:
    fout.write(repr(buf))

io.close()
