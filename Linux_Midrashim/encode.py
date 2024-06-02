def encode_string(input_string):
    encoded_bytes = []
    for char in input_string:
        byte = ord(char)
        encoded_byte = (byte ^ 5) + 50
        encoded_bytes.append(encoded_byte)
    return encoded_bytes

# Exemple d'utilisation
input_string = "python3 \"print('ok')\" > /dev/null 2>&1 &"
encoded_bytes = encode_string(input_string)

# Afficher les octets encodés sous forme hexadécimale
print("Encoded bytes:")
print(", ".join(f"0x{byte:02x}" for byte in encoded_bytes))

# Afficher les octets encodés sous forme de db statements pour l'assembly
print("\nAssembly db statements:")
print("db " + ", ".join(f"0x{byte:02x}" for byte in encoded_bytes))
