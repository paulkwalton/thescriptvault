#!/bin/bash

# Update and Upgrade Kali Linux
echo "Updating and upgrading Kali Linux..."
sudo apt update -y
sudo apt upgrade -y

# Install Sliver C2
echo "Installing Sliver C2..."
curl https://sliver.sh/install | sudo bash

# Kali Hardening Section <Start>
echo "Starting Kali Linux hardening..."

# Install security updates
echo "Installing security updates..."
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure unattended-upgrades

# Remove unnecessary services
echo "Removing unnecessary services..."
services_to_disable=(
  bluetooth.service
  avahi-daemon.service
  cups.service
  isc-dhcp-server.service
  isc-dhcp-server6.service
  slapd.service
  nfs-server.service
  bind9.service
  vsftpd.service
  dovecot.service
  smbd.service
  squid.service
  snmpd.service
)

for service in "${services_to_disable[@]}"; do
  sudo systemctl disable --now "$service"
done

# Install and configure Fail2Ban
echo "Installing and configuring Fail2Ban..."
sudo apt install -y fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Create a basic Fail2Ban configuration for SSH
echo "Creating Fail2Ban SSH configuration..."
sudo tee /etc/fail2ban/jail.d/ssh.local <<EOF
[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 86400
EOF

sudo systemctl restart fail2ban

echo "Kali Linux hardening completed."
# Kali Hardening Section <End>

# Install additional packages that are not part of kali-linux-default
sudo apt install -y default-jdk
sudo apt install -y build-essential
# windows-binaries is not a standard package. You might be looking for wine or other tools.
# Example for wine:
sudo apt install -y wine
sudo apt install -y sshuttle
sudo apt install -y openssh-server
# certipy-ad is a Python package, so you'd use pip:
sudo apt install -y python3-pip
sudo pip3 install certipy-ad
sudo apt install -y jq
sudo apt install -y macchanger
sudo apt install -y python3-impacket
sudo apt install -y git
sudo apt install -y netcat-traditional
sudo apt install -y tilix
sudo apt install -y sqlmap
sudo apt install -y gobuster
sudo apt install -y iputils-ping
# dirbuster is not in standard repos. Consider using dirb or dirsearch.
sudo apt install -y dirb
sudo apt install -y nano
sudo apt install -y nikto
# sublist3r is a Python package:
sudo pip3 install sublist3r
sudo apt install -y zeek
sudo apt install -y net-tools
# exploitdb is usually installed via searchsploit from the Metasploit Framework:
# Install Metasploit:
sudo apt install -y metasploit-framework
sudo apt install -y novnc
sudo apt install -y tcpdump
# msfpc is not a package, it is a script. You'd download and execute it.
sudo apt install -y smbclient
sudo apt install -y lldpd
sudo apt install -y enum4linux
sudo apt install -y default-mysql-client
sudo apt install -y snapd
sudo apt install -y prips
# dirsearch is a Python package:
sudo pip3 install dirsearch
# pip is already installed as part of python3-pip above.
sudo apt install -y rdesktop
# seclists is usually downloaded from GitHub.
sudo apt install -y dnsrecon
sudo apt install -y jython
sudo apt install -y sqlitebrowser
# hashid is a Python package:
sudo pip3 install hashid
# spray is a Python package:
sudo pip3 install spray
sudo apt install -y responder
sudo apt install -y yersinia
sudo apt install -y postgresql
sudo apt install -y auditd
sudo apt install -y audispd-plugins
sudo apt install -y golang-go
sudo apt install -y libpcap-dev
sudo apt install -y sshpass
# eyewitness is a Python package:
sudo pip3 install eyewitness
sudo apt install -y hping3
# sprayhound is not a standard package.
# spray is already installed above.
# goshs is not a standard package.
sudo apt install -y filezilla
sudo apt install -y powershell
sudo apt install ligolo-ng -y
sudo apt install wine -y
sudo apt install winetricks -y
sudo apt install nuclei -y 

sudo systemctl enable ssh.service
sudo systemctl start ssh.service
sudo service lldpd start
sudo service postgresql start

# Download and clone additional tools to the correct directories
echo "Downloading additional tools..."
sudo mkdir -p /opt/{sysinternals,privesc/{linux,windows},buildreview,password,network,persistence,adtools,bof,filehosting,ics,packetcapture}

# Sysinternals
wget -O /opt/sysinternals https://download.sysinternals.com/files/Procdump.zip

# Privilege Escalation (Linux)
sudo git clone https://github.com/rebootuser/LinEnum.git /opt/privesc/linux/linenum
sudo git clone https://github.com/carlospolop/PEASS-ng.git /opt/privesc/linux/peass-ng
# Privilege Escalation (Windows)
sudo git clone https://github.com/bitsadmin/wesng.git /opt/privesc/windows/exploit-suggester
sudo git clone https://github.com/antonioCoco/RemotePotato0.git /opt/privesc/windows/remotepotato
sudo git clone https://github.com/carlospolop/PEASS-ng.git /opt/privesc/windows/peass-ng
sudo git clone https://github.com/PowerShellMafia/PowerSploit.git /opt/privesc/powersploit
sudo git clone https://github.com/GhostPack/Seatbelt.git /opt/privesc/seatbelt
sudo git clone https://github.com/GhostPack/SharpUp.git /opt/privesc/sharpup
sudo git clone https://github.com/danielbohannon/Invoke-Obfuscation.git /opt/privesc/invoke-obfuscation
sudo git clone https://github.com/BeichenDream/GodPotato.git /opt/privesc/godpotato
sudo git clone https://github.com/ohpe/juicy-potato.git /opt/privesc/juicypotato
sudo git clone https://github.com/itm4n/PrintSpoofer.git /opt/privesc/printspoofer
sudo git clone https://github.com/TheWover/donut.git opt/privesc/donut
sudo git clone https://github.com/decoder-it/psgetsystem.git /opt/privesc/psgetsystem
# Build Review
sudo git clone https://github.com/OneLogicalMyth/BuildReview-Windows.git /opt/buildreview/buildreview-windows
sudo git clone https://github.com/OneLogicalMyth/PAudit.git /opt/buildreview/paudit
# Password Tools
sudo git clone https://github.com/edernucci/identity-to-hashcat.git /opt/password/identity-to-hashcat
sudo git clone https://github.com/gentilkiwi/mimikatz.git /opt/password/mimikatz
sudo git clone https://github.com/GhostPack/KeeThief.git /opt/password/keethief
sudo git clone https://github.com/gentilkiwi/kekeo.git /opt/password/kekeo
sudo git clone https://github.com/leoloobeek/LAPSToolkit.git /opt/password/lapstoolkit
sudo git clone https://github.com/GhostPack/Rubeus.git /opt/password/rubeus
# Network Tools
sudo git clone https://github.com/p0dalirius/Coercer.git /opt/network/coercer
sudo git clone https://github.com/ropnop/kerbrute.git /opt/adtools/kerbrute
sudo git clone https://github.com/lgandx/PCredz.git /opt/packetcapture/pcredz
curl https://i.jpillora.com/chisel! | bash
wget https://github.com/jpillora/chisel/releases/download/v1.10.0/chisel_1.10.0_linux_amd64.gz
sudo git clone https://github.com/SnaffCon/Snaffler.git /opt/snaffler
# Persistence Tools
sudo git clone https://github.com/Sw4mpf0x/PowerLurk.git /opt/persistence/windows/powerlurk
# Active Directory Tools (ADTools)
sudo git clone https://github.com/dirkjanm/krbrelayx.git /opt/adtools/krbrelayx
# Buffer Overflow (BOF)
sudo git clone https://github.com/fortra/nanodump.git /opt/bof/nanodump
# File Hosting
sudo git clone https://github.com/sc0tfree/updog.git /opt/filehosting/updog
# ICS (Industrial Control Systems)
sudo git clone https://github.com/ITI/ICS-Security-Tools.git /opt/ics/resources
# Install LaZagne
echo "Installing LaZagne..."
sudo git clone https://github.com/AlessandroZ/LaZagne.git /opt/lazagne
# Install BloodHound and SharpHound
echo "Getting SharpHound..."
sudo git clone https://github.com/BloodHoundAD/SharpHound.git /opt/sharphound
# Install HoaxShell
sudo git clone https://github.com/t3l3machus/hoaxshell /opt/hoaxshell
# Install Invoke Obfuscation
sudo git clone https://github.com/danielbohannon/Invoke-Obfuscation.git /opt/invoke-obfuscation
sudo git clone https://github.com/dafthack/GraphRunner.git /opt/graphrunner
sudo git clone https://github.com/OmerYa/Invisi-Shell.git /opt/invisi-shell

echo "Running apt cleanup..."
sudo apt autoremove -y
sudo apt clean
sudo apt autoclean

# System Information
echo "Displaying system information..."
sudo apt install -y neofetch
neofetch

# Additional downloads
echo "Downloading additional binaries..."
sudo wget -O /opt/icspasswords/scada.csv https://github.com/ITI/ICS-Security-Tools/blob/f829a32f98fadfa5206d3a41fc3612dd4741c8b3/configurations/passwords/scadapass.csv
sudo wget -O /opt/network/kerbrute-linux-64 https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
sudo wget -O /opt/adtools/windapsearch https://github.com/ropnop/go-windapsearch/releases/download/v0.3.0/windapsearch-linux-amd64
sudo wget -O /opt/ruler-linux64 https://github.com/sensepost/ruler/releases/download/2.4.1/ruler-linux64
sudo wget -O /opt/pingcastle https://github.com/netwrix/pingcastle/releases/download/3.3.0.1/PingCastle_3.3.0.1.zip
sudo curl https://i.jpillora.com/chisel! | bash
pip install pysmb --break-system-packages


# Configure and compile KWProcessor
echo "Configuring KWProcessor..."
cd /opt/kwprocessor/
sudo make
./kwp -z basechars/full.base keymaps/en-us.keymap routes/2-to-16-max-3-direction-changes.route > /opt/keyboard-walk-passwords.txt

# Install Python packages
echo "Installing Python packages..."
sudo pip install mitm6 pyftpdlib Cython python-libpcap

# Install Empire C2
git clone --recursive https://github.com/BC-SECURITY/Empire.git
cd Empire
./setup/checkout-latest-tag.sh
./ps-empire install -y

# Install Ngrok
curl -sSL https://ngrok-agent.s3.amazonaws.com/ngrok.asc \
	| sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null \
	&& echo "deb https://ngrok-agent.s3.amazonaws.com buster main" \
	| sudo tee /etc/apt/sources.list.d/ngrok.list \
	&& sudo apt update \
	&& sudo apt install ngrok

# Final steps
echo "Changing default SSH keys..."
sudo mkdir /etc/ssh/old_keys
sudo mv /etc/ssh/ssh_host_* /etc/ssh/old_keys
sudo dpkg-reconfigure openssh-server

# Script completion indicator
echo "Script completed successfully!"
touch /opt/script-completed-pls-del-me.txt
