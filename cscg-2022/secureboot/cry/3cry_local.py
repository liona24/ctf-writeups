import json
from collections import defaultdict

from capstone import Cs, CS_ARCH_X86, CS_MODE_16
from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_INTR, UC_HOOK_CODE
import unicorn.x86_const as x86

"""
Found key leak for 0: 72 71 36 2e 31 29 f5 82
Found key leak for 1: ce 77 9a 3a a9 b0 40 b8
Found key leak for 2: 9a 57 88 a6 7b db d6 45
Found key leak for 3: 59 8b a1 0b fe e3 01 5e
Found key leak for 4: 62 2b d7 f5 fa 46 d1 99
Found key leak for 5: f6 ac ab ae 69 86 01 4e
Found key leak for 6: 35 d0 10 4e 00 6a d7 ab
Found key leak for 7: 14 3f f4 c9 be b6 01 a7
"""

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

CAPTURED_OUTPUT = []
SIG = [0] * 8
CURRENT_ITERATION = [0]
"""
Found key leak for 0: 72 71 36 2e 31 29 f5 82
Found key leak for 1: ce 77 9a 3a a9 b0 40 b8
Found key leak for 2: 9a 57 88 a6 7b db d6 45
Found key leak for 3: 59 8b a1 0b fe e3 01 5e
Found key leak for 4: 62 2b d7 f5 fa 46 d1 99
Found key leak for 5: f6 ac ab ae 69 86 01 4e
Found key leak for 6: 35 d0 10 4e 00 6a d7 ab
Found key leak for 7: 14 3f f4 c9 be b6 01 a7
"""
KEY_PAYLOADS = [
    bytes.fromhex("72 71 36 2e 31 29 f5 82"),
    bytes.fromhex("ce 77 9a 3a a9 b0 40 b8"),
    bytes.fromhex("9a 57 88 a6 7b db d6 45"),
    bytes.fromhex("59 8b a1 0b fe e3 01 5e"),
    bytes.fromhex("62 2b d7 f5 fa 46 d1 99"),
    bytes.fromhex("f6 ac ab ae 69 86 01 4e"),
    bytes.fromhex("35 d0 10 4e 00 6a d7 ab"),
    bytes.fromhex("14 3f f4 c9 be b6 01 a7"),
]


def handle_int(emu: Uc, no: int, user_data):
    if no == 0x10:
        CAPTURED_OUTPUT.append(emu.reg_read(x86.UC_X86_REG_AL))
    elif no == 0x16:
        # read
        emu.emu_stop()
    elif no == 0x13:
        img = list(payload)
        img[-8:] = list(KEY_PAYLOADS[CURRENT_ITERATION[0]])
        img.extend(SIG)
        img = bytes(img)

        bx = emu.reg_read(x86.UC_X86_REG_BX)
        emu.mem_write(bx, img)
    else:
        # print("Unk:", no, hex(no))
        emu.emu_stop()

def handle_instr(emu: Uc, address: int, size: int, user_data):
    return
    ip = emu.reg_read(x86.UC_X86_REG_IP)
    ips.append(ip)
    """
    if ip == 0x0630:
        print("before chunk")
        x = emu.mem_read(0x0764, 8).hex()
        print("0x764:", x)

        x = emu.mem_read(0x076c, 8).hex()
        print("0x76c:", x)

    if ip == 0x0641:
        print("before encrypt")
        x = emu.mem_read(0x0764, 8).hex()
        print("0x764:", x)

        x = emu.mem_read(0x076c, 8).hex()
        print("0x76c:", x)

    if ip == 0x0649:
        print("after encrypt")
        x = emu.mem_read(0x0764, 8).hex()
        print("0x764:", x)

        x = emu.mem_read(0x076c, 8).hex()
        print("0x76c:", x)

    if ip == 0x0661:
        print("after xor")
        x = emu.mem_read(0x0764, 8).hex()
        print("0x764:", x)

        x = emu.mem_read(0x076c, 8).hex()
        print("0x76c:", x)
    """

    if ip == 0x06c2:
        # call to encrypt function
        sbox = emu.mem_read(0x0600, 256).hex()
        print("SBOX:", sbox)

        di = emu.reg_read(x86.UC_X86_REG_DI)
        key = emu.mem_read(di, 8).hex()
        print("Key:", key)

        si = emu.reg_read(x86.UC_X86_REG_SI)
        buf = emu.mem_read(si, 8).hex()
        print("Buf:", buf)

    if ip == 0x0672:
        x = emu.mem_read(0x764, 8)
        print("Desired result before encrypt (0x0764):", x.hex())
        x = emu.mem_read(0x76c, 8)
        print("?? before encrypt (0x076c):", x.hex())
        x = emu.mem_read(0x7e00, 8)
        print("Signature before encrypt (0x7e00):", x.hex())

    if ip == 0x067f:
        x = emu.mem_read(0x764, 8)
        print("Desired result after encrypt (0x0764):", x.hex())
        x = emu.mem_read(0x76c, 8)
        print("?? after encrypt (0x076c):", x.hex())
        x = emu.mem_read(0x7e00, 8)
        print("Signature after encrypt (0x7e00):", x.hex())

    return

    off = 0x7600
    if ip == 0x7cd4 - off:
        # low byte is key byte mod 8
        # high byte is unknown ??
        ax = emu.reg_read(x86.UC_X86_REG_AX)
        print(hex(ax))
    return


def encrypt(buf: list, key: list):
    # encrypt:
    for i in range(0x100):
        i = 0x100 - i
        x = buf[i % 8]
        buf[i % 8] = (((x >> 1 | x << 7) & 0xFF) - SBOX[ (key[(i - 1) % 8] + buf[(i - 1) % 8]) & 0xFF ]) & 0xFF


def decrypt(buf: list, key: list):
    # decrypt:
    for i in range(0x100):
        i = i + 1
        x = (buf[i % 8] + SBOX[ (key[(i - 1) % 8] + buf[(i - 1) % 8]) & 0xFF ]) & 0xFF
        buf[i % 8] = ((x << 1 | x >> 7) & 0xFF)

if __name__ == '__main__':

    for i in range(len(KEY_PAYLOADS)):
        IMG_BASE = 0x7c00
        ENTRY_POINT = IMG_BASE

        with open("bootloader_test", "rb") as fin:
            img = fin.read()

        emu = Uc(UC_ARCH_X86, UC_MODE_16)  # Unicorn
        emu.mem_map(0, 0x10000)
        emu.mem_write(IMG_BASE, img)

        # skip initialization shit
        # emu.mem_write(0x8000, b"\x0d" * (0xFFFF - 0x8000))

        CAPTURED_OUTPUT.clear()
        CURRENT_ITERATION[0] = i

        emu.hook_add(UC_HOOK_INTR, handle_int)
        emu.hook_add(UC_HOOK_CODE, handle_instr)

        emu.emu_start(ENTRY_POINT, 0)

        target = bytes.fromhex("".join(map(chr, CAPTURED_OUTPUT[-16:])))
        print(target.hex())

        SBOX = list(bytes.fromhex("fabc007cbe007cbf0006b98000fcf366a566ea190600000000fbb80202bb007cb281b90100b600cd13bf007c8d36640789f88d3e6c07b90200f366a589c783ee0866e85500000089fb8d3e6c07b908008a248a0530e088044647e2f489df83ee0883c70889f82d007e75c5be007e8d3eed0666e84a000000be007e8d3e6407b90800f3a67505b8007cffe08d360007b40eac3c000f848c00cd10ebf5b90001ac4e31d2565701d78a2500e0bb0006d74283e20701d68a2400e0d0c088045f5ee2e2c3b900015689ca4a83e207678a2416678a0417d501bb0006d74283e2076601d68a24d0cc28c488245ee2d9c300000000000000000000000000000000000000"))

        img = list(payload)
        img[-8:] = list(KEY_PAYLOADS[CURRENT_ITERATION[0]])

        for kb in range(256):
            SBOX[237 + CURRENT_ITERATION[0]] = kb
            buf = [0] * 8
            for i in range(0, len(img), 8):
                key = img[i:i+8]

                tmpBuf = buf.copy()
                decrypt(tmpBuf, key)
                buf = [ a ^ b for a, b in zip(buf, tmpBuf) ]

            if bytes(buf) == target:
                print(f"Found keybyte {CURRENT_ITERATION[0]}:", hex(kb))
                break


    exit(0)


    SBOX = bytes.fromhex("fabc007cbe007cbf0006b98000fcf366a566ea190600000000fbb80202bb007cb281b90100b600cd13bf007c8d36640789f88d3e6c07b90200f366a589c783ee0866e85500000089fb8d3e6c07b908008a248a0530e088044647e2f489df83ee0883c70889f82d007e75c5be007e8d3eed0666e84a000000be007e8d3e6407b90800f3a67505b8007cffe08d360007b40eac3c000f848c00cd10ebf5b90001ac4e31d2565701d78a2500e0bb0006d74283e20701d68a2400e0d0c088045f5ee2e2c3b900015689ca4a83e207678a2416678a0417d501bb0006d74283e2076601d68a24d0cc28c488245ee2d9c341004100410041000000000000000000000000")

    buf = list(bytes.fromhex("99ae4fd02538b4d4"))
    key = list(bytes.fromhex("4100410041004100"))

    def encrypt(buf: list, key: list):
        # encrypt:
        for i in range(0x100):
            i = 0x100 - i
            x = buf[i % 8]
            buf[i % 8] = (((x >> 1 | x << 7) & 0xFF) - SBOX[ (key[(i - 1) % 8] + buf[(i - 1) % 8]) & 0xFF ]) & 0xFF


    def decrypt(buf: list, key: list):
        # decrypt:
        for i in range(0x100):
            i = i + 1
            x = (buf[i % 8] + SBOX[ (key[(i - 1) % 8] + buf[(i - 1) % 8]) & 0xFF ]) & 0xFF
            buf[i % 8] = ((x << 1 | x >> 7) & 0xFF)

    buf = [0] * 8
    key = [0] * 8

    # 75e07c7ba7ab7a14
    buf = list(bytes.fromhex("f44ba391005113d0"))

    print("---")
    decrypt(buf, key)

    img = bytes([0] * 512)

    buf = [0] * 8
    for i in range(0, len(img), 8):
        key = img[i:i+8]

        tmpBuf = buf.copy()
        decrypt(tmpBuf, key)
        print(bytes(tmpBuf).hex())
        buf = [ a ^ b for a, b in zip(buf, tmpBuf) ]
        print(bytes(buf).hex())

    print(bytes(buf).hex())
