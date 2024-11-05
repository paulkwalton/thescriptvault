#!/bin/bash

# Update and Upgrade Kali Linux
echo "Updating and upgrading Kali Linux..."
sudo apt update -y
sudo apt full-upgrade -y

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
echo "Installing additional packages..."
additional_packages=(
  default-jdk
  build-essential
  windows-binaries
  sshuttle
  openssh-server
  certipy-ad
  jq
  macchanger
  python3-impacket
  git
  netcat-traditional
  tilix
  sqlmap
  gobuster
  iputils-ping
  dirbuster
  dirb
  nano
  nikto
  sublist3r
  zeek
  net-tools
  exploitdb
  novnc
  tcpdump
  msfpc
  smbclient
  lldpd
  enum4linux
  default-mysql-client
  snapd
  prips
  dirsearch
  pip
  rdesktop
  seclists
  dnsrecon
  jython
  sqlitebrowser
  hashid
  spray
  responder
  yersinia
  postgresql
  auditd
  audispd-plugins
  golang-go
  libpcap-dev
  sshpass
  eyewitness
  hping3
  sprayhound
  spray
  goshs
  filezilla
)

sudo apt install -y "${additional_packages[@]}"
sudo systemctl enable ssh.service
sudo systemctl start ssh.service
sudo service lldpd start
sudo service postgresql start

# Download and clone additional tools to the correct directories
echo "Downloading additional tools..."
sudo mkdir -p /opt/{sysinternals,privesc/{linux,windows},buildreview,password,network,persistence,adtools,bof,filehosting,ics,packetcapture}

# Sysinternals
# (No repositories in this category for now)

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
# Install CherryTree
# Automated Cleanup and Maintenance
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

# Configure and compile KWProcessor
echo "Configuring KWProcessor..."
cd /opt/kwprocessor/
sudo make
./kwp -z basechars/full.base keymaps/en-us.keymap routes/2-to-16-max-3-direction-changes.route > /opt/keyboard-walk-passwords.txt

# Install Python packages
echo "Installing Python packages..."
sudo pip install mitm6 pyftpdlib Cython python-libpcap

# Final steps
echo "Changing default SSH keys..."
sudo mkdir /etc/ssh/old_keys
sudo mv /etc/ssh/ssh_host_* /etc/ssh/old_keys
sudo dpkg-reconfigure openssh-server

# Script completion indicator
echo "Script completed successfully!"
touch /opt/script-completed-pls-del-me.txt
