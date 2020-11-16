# usage: python3 decoder.py plaintextfile ciphertextfile

import sys
import struct
import binascii
import hashlib
from itertools import product

def rol64(x):
    return (x << 1) & 0xffffffffffffffff | ((x & 0xffffffffffffffff) >> 63)

def ror64(x):
    return ((x & 0xffffffffffffffff) >> 1) | ((x << 63) & 0xffffffffffffffff)

def decipher(target_file, hex_key):
    """Displays a command which can be used to decipher the given target file"""
    key = binascii.unhexlify(hex_key)

    h = hashlib.md5()
    h.update(key)
    digest = h.hexdigest()

    key_file = f"key_{digest[:4]}"
    with open(key_file, 'wb') as f:
        f.write(key)

    with open(target_file, 'r') as f:
        content = f.read()

    content = digest + content[len(digest):]

    new_target = f"{target_file}.{digest[:4]}"

    with open(new_target, 'w') as f:
        f.write(content)

    print(f"cat {new_target} | ./go_cipher_linux --key={key_file} --decrypt")


def check(e, t, x, y, z):
    return all([ ((ti - x) & 0xff) ^ y ^ z == ei for (ti, ei) in zip(t, e) ])

def extract_key(ciphertext, plaintext):
    key_sum = ciphertext[:0x10]
    ciphertext = ciphertext[0x10:]

    assert (len(ciphertext) == len(plaintext)), f"C: {len(ciphertext)} P: {len(plaintext)}"

    e = [ciphertext[i*64] for i in range(4)]
    t = [plaintext[i*64] for i in range(4)]

    raw_candidates_next = []
    for (x, y, z) in product(range(256), range(256), range(256)):
        #if ((t - x) & 0xff) ^ y ^ z == e:
        if check(e, t, x, y, z):
            raw_candidates_next.append((x, y, z))

    keys = []

    for c in raw_candidates_next:
        q = [(c, 1)]

        while len(q) > 0:
            (x, y, z), i = q.pop()

            if i == 64:
                x = ror64(x)
                y = rol64(y)
                z = rol64(z)
                bx = struct.pack('<Q', x)
                by = struct.pack('<Q', y)
                bz = struct.pack('<Q', z)

                # we are happy if we find any key
                return binascii.hexlify(bx + by + bz)

            # pretty bad coding style, but it is enough for the input we got
            if i + 64 * 3 < len(ciphertext):
                e = [ciphertext[i+j*64] for j in range(4)]
                t = [plaintext[i+j*64] for j in range(4)]
            else:
                e = [ciphertext[i], ciphertext[i+64], ciphertext[i+128]]
                t = [plaintext[i], plaintext[i+64], plaintext[i+128]]

            xr = ror64(x)
            yr = rol64(y)
            zr = rol64(z)
            for bit_x, bit_y, bit_z in product([0, 1], [0, 1], [0, 1]):
                x_ = (xr | (bit_x << 7))
                y_ = (yr | bit_y)
                z_ = (zr | bit_z)

                xb = x_ & 0xff
                yb = y_ & 0xff
                zb = z_ & 0xff
                if check(e, t, xb, yb, zb):
                    q.append(((x_, y_, z_), i+1))

    raise RuntimeError("No key found!")

if __name__ == '__main__':

    with open(sys.argv[1], 'rb') as f:
        plain = list(map(int, f.read()))

    with open(sys.argv[2], 'r') as f:
        cipher = list(map(int, binascii.unhexlify(f.read())))

    key = extract_key(cipher, plain)
    print("Found key: ", key)
    decipher(sys.argv[2], key)