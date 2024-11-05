#!/bin/bash

# Prompt for IP address, username
read -p "Enter the IP address: " ip_address
read -p "Enter the username: " username

# Set default MS SQL port
port=1433

# Check if the MS SQL port is open
if timeout 2 bash -c "</dev/tcp/$ip_address/$port"; then
    echo "Port $port is open on $ip_address."
    
    # Connect using mssqlclient.py without preempting the password
    mssqlclient.py "${username}@${ip_address}" -windows-auth
else
    echo "Port $port is not open on $ip_address. Please check the server or network settings."
fi
