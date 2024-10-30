#!/usr/bin/python3
import os
url="http://10.129.229.2/v1"
os.system ("wpscan --url %s --enumerate p,t,u --plugins-detection aggressive --detection-mode aggressive --random-user-agent --force --passwords /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt"% url)
os.system ("feroxbuster -u %s -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -d 2 -k -E -B -g -r -C 403,404,301,503,500 -x php,asp,aspx,doc,docx,xlx,xlsx,txt,cfg,pdf,zip,bak -t 25"% url)
