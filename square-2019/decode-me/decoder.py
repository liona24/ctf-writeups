#!/usr/bin/python
import sys
from collections import Counter
import base64
import string

VALID_B64 = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')

def f(x, r):
    return (ord(x) - ord(r) + len(string.printable)) % len(string.printable)

def f_inv(diff, r):
    rv = []
    for x in string.printable:
        if f(x, r) == diff and x in VALID_B64:
            rv.append(x)
    return rv

def decode(src_file):
    with open(src_file, 'rb') as f:
        src = f.read()

    i = 0
    decoded = []
    while i < len(src):
        r_unique = set()
        r_all = []
        while i < len(src) and src[i] != '\x00':
            r_unique.add(src[i])
            r_all.append(src[i])
            i += 1

        counts = Counter(r_all)

        for r in r_all[:len(r_unique)]:
            diff = counts[r]
            x = f_inv(diff, r)
            if len(x) > 1:
                # for debugging reasons
                print x
            else:
                decoded.append(x[0])
        i += 1
    return base64.b64decode(''.join(decoded))

if __name__ == '__main__':
    fname = sys.argv[1]
    print decode(fname)