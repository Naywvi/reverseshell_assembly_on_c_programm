# Shellcode Integration Example

## Description

This project demonstrates how to integrate assembly code within a C program to execute a reverse shell after displaying a "Hello, World!" message. The reverse shell connects to `localhost` on port `4444`.

## Files

- `shellcode.s`: Contains the assembly code for the reverse shell.
- `wrapper.c`: A C wrapper that allows calling the assembly code from the main C program.
- `main.c`: The main C program that prints "Hello, World!" and then executes the reverse shell.
- `build.sh`: A script to compile and link all the files into an executable.

## Usage

### Prerequisites

Ensure you have the following tools installed:
- `nasm` for assembling the assembly code.
- `gcc` for compiling and linking the C code.
- `netcat` (`nc`) for setting up a listener.

### Steps

1. **Make the `build.sh` script executable**:

    ```sh
    chmod +x build.sh
    ```

2. **Run the `build.sh` script to compile and link the program**:

    ```sh
    ./build.sh
    ```

3. **Open a separate terminal and start a Netcat listener on port 4444**:

    ```sh
    nc -lvp 4444
    ```

4. **Run the compiled program**:

    ```sh
    ./myprogram
    ```

    You should see the message "Hello, World!" in your terminal.

5. **Check the Netcat listener terminal**:

    If everything works correctly, you should see a connection and be dropped into a shell session.

## Notes

- This example is designed to run on `localhost` and connects back to `127.0.0.1` on port `4444`.
- Ensure you have `nasm`, `gcc`, and `netcat` (`nc`) installed on your system.
- Use this code responsibly and only in controlled environments for educational purposes.

## Troubleshooting

- **Permission Denied**: Ensure you have the necessary permissions to execute the scripts and compiled programs.
- **Connection Issues**: Make sure the Netcat listener is running before executing the compiled program.

## Build Script Explanation

The `build.sh` script performs the following steps:

1. Assembles the assembly code in `shellcode.s` into an object file.
2. Compiles the C wrapper in `wrapper.c` into an object file.
3. Compiles the main C program in `main.c` into an object file.
4. Links all the object files into a single executable named `myprogram`.
5. Makes the `myprogram` executable.

```sh
#!/bin/bash

# Assemble the assembly code
nasm -f elf64 shellcode.s -o shellcode.o

# Compile the C wrapper
gcc -c wrapper.c -o wrapper.o

# Compile the main C program
gcc -c main.c -o main.o

# Link the object files to create the executable
gcc main.o wrapper.o shellcode.o -o myprogram

# Make the executable runnable
chmod +x myprogram

echo "Build completed successfully. You can run ./myprogram to execute the program."

```

Copy and paste the above content into your README file. This README provides a detailed explanation of the code, instructions on how to build and run the program, and notes on usage and troubleshooting, without showing the actual code.

ps : Naywvi