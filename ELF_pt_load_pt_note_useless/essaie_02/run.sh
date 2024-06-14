nasm -f elf64 injector.asm -o injector.o
ld injector.o -o injector
./injector
ls -l infected.elf
hexdump -C infected.elf | tail
chmod +x infected.elf
./infected.elf
