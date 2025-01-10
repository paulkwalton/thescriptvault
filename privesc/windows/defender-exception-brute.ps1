# Check if the Windows Defender Operational log is available
$logName = "Microsoft-Windows-Windows Defender/Operational"
if (-not (Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue)) {
    Write-Output "Error: The log '$logName' does not exist or cannot be accessed."
    exit
}

# Retrieve events with Event ID 5007 containing the word "exclusion"
try {
    $events = Get-WinEvent -LogName $logName -FilterXPath "*[System/EventID=5007]" -ErrorAction Stop | Where-Object {
        $_.Message -match "exclusion"
    }

    # Extract only the 'New value' lines containing "exclusion" and deduplicate the results
    $uniqueNewValues = $events | ForEach-Object {
        if ($_.Message -match "New value: (.+)") {
            $value = $matches[1].Trim()
            # Include any value containing the word "exclusion"
            if ($value -match "exclusion") {
                $value
            }
        }
    } | Sort-Object -Unique

    # Add a title explaining the content and display it in the PowerShell window
    $title = "Excluded Antivirus Folders and Paths:\n"
    Write-Output $title

    # Display the unique 'New value' entries in a readable format
    $uniqueNewValues | ForEach-Object {
        Write-Output $_
    }
} catch {
    Write-Output "Error: Unable to retrieve or export events. Details: $_"
}
 
