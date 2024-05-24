#!/bin/bash

# Assembler le code assembleur
nasm -f elf64 shellcode.s -o shellcode.o

# Compiler le wrapper C
gcc -c wrapper.c -o wrapper.o

# Compiler le programme principal en C
gcc -c main.c -o main.o

# Lier les fichiers objets pour créer l'exécutable
gcc main.o wrapper.o shellcode.o -o hello_world

# Rendre l'exécutable prêt à être exécuté
chmod +x hello_world

rm shellcode.o
rm wrapper.o
rm main.o

echo "Build completed successfully. You can run ./hello_world to execute the program.

"

./hello_world