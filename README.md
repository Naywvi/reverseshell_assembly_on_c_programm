# 🚀 Reverse Shell Code Execution Repository

Bienvenue dans ce dépôt de démonstration d'exécution de code shell inversé ! Ce dépôt contient deux projets distincts, chacun utilisant une méthode différente pour intégrer et exécuter du shellcode dans un programme cible.

## 📁 Structure du Dépôt

Ce dépôt est organisé en deux dossiers principaux :

1. **Exploit PT_NOTE/PT_LOAD avec Midrashim**
2. **Injection de Code Directe**

### 1. Exploit PT_NOTE/PT_LOAD avec Midrashim

Ce projet démontre comment exploiter une vulnérabilité PT_NOTE/PT_LOAD avec Midrashim pour intégrer du shellcode dans un exécutable ELF sous Linux et l'exécuter de manière invisible.

#### 📜 Description du Projet

Ce projet contient les fichiers suivants :

- `Linux.Midrashim.asm` : Le shellcode en Assembly qui crée une connexion inversée.
- `main.c` : Un programme C minimal pour démontrer l'exécution du shellcode.
- `run.sh` : Un script bash qui assemble, compile et exécute le shellcode avec un programme C minimal.

Ce projet utilise une technique avancée d'exploitation basée sur les sections PT_NOTE et PT_LOAD des fichiers ELF (Executable and Linkable Format). Le but est d'injecter du code malveillant dans un exécutable en profitant de la manière dont les chargeurs de programme traitent ces sections. En utilisant Midrashim, nous modifions les segments PT_NOTE pour y insérer du code shell inversé, puis faisons en sorte que ce segment soit traité comme un segment PT_LOAD. Cela permet au code inséré de s'exécuter comme s'il faisait partie intégrante de l'exécutable original.

### 2. Injection de Code Directe

Ce projet montre comment ajouter directement du code dans un fichier exécutable, rendant ce projet compatible avec les systèmes d'exploitation Linux et Windows.

### 📁 Structure du Répertoire

```sh
├── README.md
├── Linux_and_windows
│   ├── README.md
│   ├── run.sh
│   └── reverse_shell.asm
└── Linux_Midrashim
    ├── README.md
    ├── run.sh
    └── Linux.Midrashim.asm
```

## ⚠️ Avertissement

**Attention** : L'exécution de ce type de code comporte des risques de sécurité. Utilisez ce dépôt uniquement dans un environnement de test sécurisé et à des fins éducatives. Ne jamais exécuter de code non vérifié ou potentiellement malveillant sur des systèmes de production.

---

✨ **Créateur** : Naywvi

Profitez de votre exploration de ce dépôt de démonstration d'exécution de code shell inversé ! 🚀
