import sys
import struct

MEMORY = [0] * 65536

my_data = [ 0x4a, 0x6a, 0x5b, 0x60, 0xa0, 0x64, 0x92, 0x7d, 0xcf, 0x42, 0xeb, 0x46, 0x00, 0x17, 0xfd, 0x50, 0x31, 0x67, 0x1f, 0x27, 0x76, 0x77, 0x4e, 0x31, 0x94, 0x0e, 0x67, 0x03, 0xda, 0x19, 0xbc, 0x51 ]

def reset_memory():
    for i in range(len(MEMORY)):
        MEMORY[i] = 0

    for i, d in enumerate(my_data):
        MEMORY[128 + i] = d


CALL_COUNTERS = [0]

def load_i32(addr):
    rv = struct.unpack('<I', bytes(MEMORY[addr:addr+4]))[0]
    # print("LOAD i32", addr, " --> ", rv)
    CALL_COUNTERS[-1] += 1
    return rv


def store_i32(addr, value):
    # print("STORE", addr, " --> ", value)
    value = value & 0xffffffff
    values = list(map(int, struct.pack('<I', value)))
    MEMORY[addr:addr+4] = values
    CALL_COUNTERS[-1] += 1


def load_i32_8u(addr):
    rv = struct.unpack('<B', bytes([MEMORY[addr]]))[0]
    # print("LOAD u8", addr, " --> ", rv)
    CALL_COUNTERS[-1] += 1
    return rv


def validate():
    l0 = 0
    while True: # L2
        if l0 == 32:
            return 1

        l1 = 0
        l2 = 2

        while True: # L4
            if l1 == l0:
                break

            i0 = l1 * 4 + 256
            i0 = load_i32(i0)

            i0 *= l2
            l2 = i0

            l1 += 1

        i0 = l0 * 4 + 256
        i1 = l2 + 1

        store_i32(i0, i1)

        i0 = load_i32_8u(l0)

        i1 = l0 + 128
        i1 = load_i32_8u(i1)

        i0 ^= i1

        i1 = l0 * 4 + 256
        i1 = load_i32_8u(i1)

        if i0 != i1:
            return 0

        l0 += 1

    raise Exception("Not allowed")


def argmax(iterable):
    it = iter(iterable)
    mx = next(it)
    ix = 0

    for i, v in enumerate(it, 1):
        if v > mx:
            ix = i
            mx = v

    return ix


def brute_force():

    result = []
    for i in range(128):
        CALL_COUNTERS.clear()
        for b in range(256):
            initial_memory = result + (128 - i) * [b]

            CALL_COUNTERS.append(0)
            reset_memory()
            MEMORY[:128] = initial_memory

            if validate() == 1:
                return result + [b]

        result.append(argmax(CALL_COUNTERS))

    return result


if __name__ == '__main__':
    """
    reset_memory()
    MEMORY[:128] = list(map(ord, 'Impossible is for the unwilling.'.ljust(128, '\x00')))
    print(validate())
    """

    print(brute_force())