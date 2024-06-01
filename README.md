# 🚀 Reverse Shell Code Execution

Bienvenue dans ce projet de démonstration d'exécution de code shell inversé ! Ce projet montre comment intégrer du shellcode dans un programme C et l'exécuter de manière invisible.

## 📝 Prérequis

Assurez-vous que les dépendances suivantes sont installées sur votre système :

- `nasm` - Assembleur pour le shellcode
- `netcat (nc)` - Outil de mise en réseau pour écouter les connexions
- `gcc` - Compilateur C

## 📜 Description du Projet

Ce projet contient les fichiers suivants :

- `reverse_shell.asm` : Le shellcode en Assembly qui crée une connexion inversée.
- `run.sh` : Un script bash qui assemble, compile et exécute le shellcode avec un programme C minimal.

## 🚀 Utilisation

### Étapes pour exécuter le script :

1. Assurez-vous que `run.sh` est exécutable (Linux uniquement).
   ```bash
   chmod +x run.sh
   ```
2. Exécutez le script :
   ```sh
   ./run.sh
   ```

### Que fait le script `run.sh` ?

1. **Vérifie les dépendances** : Le script s'assure que `nasm`, `nc`, et `gcc` sont installés.
2. **Ouvre un terminal et démarre Netcat** : Si le port 4444 n'est pas déjà ouvert, il ouvre un terminal et démarre Netcat pour écouter sur le port 4444.
3. **Assemble le shellcode** : Utilise `nasm` pour assembler `reverse_shell.asm` en un fichier objet.
4. **Crée un fichier source C minimal** : Génère un fichier `main.c` qui imprime "Hello, World!".
5. **Compile et lie le programme C avec le shellcode** : Utilise `gcc` pour compiler et lier `main.c` avec `reverse_shell.o` en un exécutable `shellcode_runner`.
6. **Exécute le programme compilé** : Lance l'exécutable généré.
7. **Nettoie les fichiers temporaires** : Supprime les fichiers temporaires `main.c` et `reverse_shell.o` de la racine.

## 📁 Structure du Répertoire

```
├── README.md
├── reverse_shell.asm
├── run.sh
├── shellcode_runner
└── execution_du_code
   ├──── main.c
   └──── reverse_shell.o

```

## ⚠️ Avertissement

**Attention** : L'exécution de ce type de code comporte des risques de sécurité. Utilisez ce projet uniquement dans un environnement de test sécurisé et à des fins éducatives. Ne jamais exécuter de code non vérifié ou potentiellement malveillant sur des systèmes de production.

---

✨ **Créateur** : Naywvi

Profitez de votre exploration de ce projet de démonstration d'exécution de code shell inversé ! 🚀
