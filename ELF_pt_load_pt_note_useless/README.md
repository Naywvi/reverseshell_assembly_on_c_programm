# Infection d'un Fichier ELF avec un Shellcode Reverse Shell

## Description

Ce projet consiste à infecter un fichier ELF simple avec un shellcode qui crée un reverse shell. L'infection utilise la méthode `PT_NOTE` vers `PT_LOAD`. Le projet comprend la compilation d'un fichier C, l'assemblage d'un shellcode en assembly, et l'injection du shellcode dans le fichier ELF.

## Structure des Fichiers

- `hello.c` : Fichier source C simple qui imprime "Hello, World!".
- `infect.asm` : Fichier d'assembly contenant le shellcode.
- `inject.py` : Script Python utilisant `pwntools` pour injecter le shellcode dans le fichier ELF.
- `infect.sh` : Script shell automatisant tout le processus.
- `README.md` : Ce fichier de documentation.

## Prérequis

- GCC : Pour compiler le fichier C.
- NASM : Pour assembler le shellcode.
- LD : Pour lier le shellcode assemblé.
- Python 3 : Pour exécuter le script d'injection.
- `pwntools` : Bibliothèque Python pour manipuler les fichiers ELF. Installez-la avec `pip install pwntools`.

## Étapes

### 1. Création des Fichiers

Créez les fichiers `hello.c`, `infect.asm`, `inject.py`, et `infect.sh` avec les contenus suivants.

#### `hello.c`

```c
#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    return 0;
}
```

# Référence

## Executable and Linkable Format - Wikipedia :

### https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#Tools

## ELF Manipulation Example :

### https://tmpout.sh/1/2.html

## ELF Virus Example :

### https://gist.github.com/x0nu11byt3/bcb35c3de461e5fb66173071a2379779

## ELF Program Headers :

### https://refspecs.linuxbase.org/elf/gabi4+/ch5.pheader.html

## ELF Format - OSDev Wiki :

### https://wiki.osdev.org/ELF

## Linux Midrashim ELF Virus :

### https://www.guitmz.com/linux-midrashim-elf-virus/

## Midrashim GitHub Repository :

### https://github.com/guitmz/midrashim/blob/main/Linux.Midrashim.asm
