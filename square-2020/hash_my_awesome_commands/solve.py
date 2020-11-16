import math
import base64
import statistics

from pwn import *

# flag: flag{d1d_u_t4k3_the_71me_t0_appr3c14t3_my_c0mm4nd5}
# flag|ndAoSzx/CbizTqNBB5cz3t6XGFEGbQwIc9i7SawgTKE=

debug_command = b"debug|9W5iVNkvnM6igjQaWlcN0JJgH+7pComiQZYdkhycKjs="

hmac = [0] * 32

def get_flag_cmd(hmac):
    return b"flag|" + base64.encodebytes(bytes(hmac))

c = remote("challenges.2020.squarectf.com", 9020)
c.recvuntil(b"command: ")

# enable debug mode
c.sendline(debug_command)

for bi in range(len(hmac)):
    # perform n trials for each byte. Sometimes 3 is not enough cause of 
    # some (server-side) hiccups. 
    # We can continue where we left off though
    # A "hiccup" can be identified by examining the timings 
    # and finding that they did not increase significantly with respect
    # to the previous ones
    trials = 3
    timings = []
    for _ in range(trials):
        ts = []
        for i in range(256):
            hmac[bi] = i

            c.recvuntil(b"command: ")
            c.send(get_flag_cmd(hmac))
            c.recvuntil(b"took")
            t = c.recvline()
            valid = c.recvline()

            if b"invalid" not in valid:
                print(get_flag_cmd(hmac))
                exit(0)

            t = int(t.lstrip().split(b" ")[0])
            ts.append(t)

        timings.append(ts)

    avg = list(map(statistics.median, list(zip(*timings))))
    print("Timings:", avg)
    mx = -1
    mi = -1
    for i, avgi in enumerate(avg):
        if avgi > mx:
            mx = avgi
            mi = i

    assert mi > -1
    hmac[bi] = mi
    print("HMAC:", hmac[:bi + 1])
