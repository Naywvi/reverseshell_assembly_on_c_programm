#!/bin/bash

gcc -no-pie -o hello hello.c
nasm -f elf64 -o infect.o infect.asm
ld -o infect infect.o
python3 inject.py
chmod +x hello_infected
./hello_infected
