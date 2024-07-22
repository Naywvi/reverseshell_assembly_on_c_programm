#!/usr/bin/env python3
from pwn import *

context(arch="amd64", os="linux")
elf = ELF("/challenge/babyjail_level1", checksec=False)
p = process(["/challenge/babyjail_level1", "flag"], cwd="/")
p.interactive()