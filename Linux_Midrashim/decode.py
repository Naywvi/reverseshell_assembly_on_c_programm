encoded_bytes = [
    0x59, 0x7c, 0x95, 0x95, 0x57, 0x9e, 0x9d, 0x57
]

decoded_chars = []
for byte in encoded_bytes:
    decoded_byte = (byte - 50) ^ 5
    decoded_chars.append(chr(decoded_byte))

decoded_string = ''.join(decoded_chars)
print(decoded_string)
