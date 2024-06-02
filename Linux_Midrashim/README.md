# 🚀 Reverse Shell Code Execution - vulnérabilité PT_NOTE/PT_LOAD avec Midrashim

Bienvenue dans ce projet de démonstration d'exécution de code shell inversé ! Ce projet montre comment exploiter une vulnérabilité PT_NOTE/PT_LOAD avec Midrashim pour intégrer du shellcode dans un programme et l'exécuter de manière invisible. Ce projet est uniquement utilisable sur Linux.
Ce projet utilise une technique avancée d'exploitation basée sur les sections PT_NOTE et PT_LOAD des fichiers ELF (Executable and Linkable Format). Le but est d'injecter du code malveillant dans un exécutable en profitant de la manière dont les chargeurs de programme traitent ces sections.

En particulier, la section PT_NOTE est souvent utilisée pour stocker des informations de débogage et d'autres métadonnées, mais elle est généralement ignorée par le chargeur de programme lors de l'exécution. En revanche, les segments PT_LOAD contiennent les informations de segment de programme que le chargeur lit et mappe en mémoire pour exécution. En utilisant Midrashim, nous modifions les segments PT_NOTE pour y insérer du code shell inversé, puis faisons en sorte que ce segment soit traité comme un segment PT_LOAD. Cela permet au code inséré de s'exécuter comme s'il faisait partie intégrante de l'exécutable original.

Cette méthode d'exploitation est puissante car elle permet de cacher le code malveillant dans des sections du fichier binaire qui sont habituellement ignorées, échappant ainsi à de nombreuses méthodes de détection. En utilisant cette technique, le projet démontre une approche sophistiquée pour la création de backdoors furtives dans des exécutables Linux. Cependant, il est crucial de noter que ce type de technique doit être utilisé uniquement à des fins éducatives et de recherche dans des environnements contrôlés, et jamais sur des systèmes de production ou sans autorisation préalable, en raison des risques de sécurité élevés qu'elle implique.

## 📝 Prérequis

Assurez-vous que les dépendances suivantes sont installées sur votre système :

- `fasm` - Assembleur pour le shellcode
- `gcc` - Compilateur C

## 📜 Description du Projet

Ce projet contient les fichiers suivants :

- `Linux.Midrashim.asm` : Le shellcode en Assembly qui crée une connexion inversée.
- `main.c` : Un programme C minimal pour démontrer l'exécution du shellcode.
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

1. **Assemble le shellcode** : Utilise `fasm` pour assembler `Linux.Midrashim.asm` en un exécutable.
2. **Vérifie le type du fichier généré** : Utilise `file` pour afficher des informations sur le type du fichier généré.
3. **Calcule le SHA-256 du fichier généré** : Utilise `sha256sum` pour calculer et afficher le checksum SHA-256 du fichier généré.
4. **Compile le programme C** : Utilise `gcc` pour compiler `main.c` et générer l'exécutable `reverse_shell_Midrashim`.
5. **Exécute l'exécutable assemblé** : Lance `Linux.Midrashim`.
6. **Exécute l'exécutable compilé** : Lance `reverse_shell_Midrashim`.

## 📁 Structure du Répertoire

```sh
├── README.md
├── main.c
├── run.sh
└── Linux.Midrashim.asm

```

## ⚠️ Avertissement

**Attention** : L'exécution de ce type de code comporte des risques de sécurité. Utilisez ce projet uniquement dans un environnement de test sécurisé et à des fins éducatives. Ne jamais exécuter de code non vérifié ou potentiellement malveillant sur des systèmes de production.

---

✨ **Créateur** : Naywvi

Profitez de votre exploration de ce projet de démonstration d'exécution de code shell inversé ! 🚀
