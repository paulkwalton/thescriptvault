#!/bin/bash

# Prompt user for the location of the KeePass database file
read -p "Enter the path to the KeePass database file: " keepass_path

# Check if the KeePass database file exists
if [[ ! -f "$keepass_path" ]]; then
    echo "The file $keepass_path does not exist."
    exit 1
fi

# Define the hash file path in the user's Documents folder using the HOME variable
hash_file="$HOME/Documents/$(basename "$keepass_path").hash"

# Convert the KeePass database into a hash format using keepass2john
if keepass2john "$keepass_path" > "$hash_file"; then
    echo "Hash file saved to $hash_file"
else
    echo "Failed to create the hash file."
    exit 1
fi

# Define the wordlist path
wordlist_path="/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"

# Check if the wordlist exists
if [[ ! -f "$wordlist_path" ]]; then
    echo "The wordlist file $wordlist_path does not exist."
    exit 1
fi

# Use John the Ripper to crack the hash
john --wordlist="$wordlist_path" "$hash_file"

# Inform the user that the process is complete
echo "John the Ripper has completed. Check the output above for results."
