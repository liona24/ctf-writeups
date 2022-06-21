import json
from collections import defaultdict

from capstone import Cs, CS_ARCH_X86, CS_MODE_16
from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_INTR, UC_HOOK_CODE
import unicorn.x86_const as x86

dis = Cs(CS_ARCH_X86, CS_MODE_16)  # Capstone

dis.detail = True

ips = []

# for 2rev_dump_flag.bin
SIG = bytes.fromhex("4b5f97aba7c20192")

def handle_int(emu: Uc, no: int, user_data):
    if no == 0x10:
        print("Out:", chr(emu.reg_read(x86.UC_X86_REG_AL)))
        # with open("ip.json", "w") as fout:
        #    json.dump(ips, fout)
        # emu.emu_stop()
        return
    elif no == 0x16:
        # read
        emu.reg_write(x86.UC_X86_REG_AL, 0)
        print("No more input!")
        emu.emu_stop()
    elif no == 0x13:
        with open("2rev_dump_flag.bin", "rb") as fin:
            img = fin.read()

        img = img + bytes(SIG)
        bx = emu.reg_read(x86.UC_X86_REG_BX)
        emu.mem_write(bx, img)
    else:
        print("Unk:", no, hex(no))
        emu.emu_stop()

def handle_instr(emu: Uc, address: int, size: int, user_data):
    ip = emu.reg_read(x86.UC_X86_REG_IP)
    ips.append(ip)

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

        emu.emu_stop()

    return

    off = 0x7600
    if ip == 0x7cd4 - off:
        # low byte is key byte mod 8
        # high byte is unknown ??
        ax = emu.reg_read(x86.UC_X86_REG_AX)
        print(hex(ax))
    return



with open("bootloader_test", "rb") as fin:
    img = fin.read()


baseline = None

IMG_BASE = 0x7c00
ENTRY_POINT = IMG_BASE

emu = Uc(UC_ARCH_X86, UC_MODE_16)  # Unicorn
emu.mem_map(0, 0x10000)
emu.mem_write(IMG_BASE, img)

# skip initialization shit
# emu.mem_write(0x8000, b"\x0d" * (0xFFFF - 0x8000))

emu.hook_add(UC_HOOK_INTR, handle_int)
emu.hook_add(UC_HOOK_CODE, handle_instr)

emu.emu_start(ENTRY_POINT, 0)


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

print(bytes(buf).hex()) # = 4b5f97aba7c20192

with open("2rev_dump_flag.bin", "rb") as fin:
    img = fin.read()
with open("2rev_dump_flag.bin.signed", "wb") as fout:
    fout.write(img)
    fout.write(bytes(buf))
