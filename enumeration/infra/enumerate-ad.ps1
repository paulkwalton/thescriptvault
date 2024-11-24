<#
.SYNOPSIS
    PowerShell Script for Comprehensive Active Directory Security Checks on a Non-Domain Joined Machine.

.DESCRIPTION
    This script performs various security checks against an Active Directory environment. It includes pauses between sections to reduce load on the Domain Controller, as it often runs on mission-critical systems.
    The script collects findings and exports them to an HTML report for review.
    Install Active Directory Module
    Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
    Install Group Policy Management Tools
    Add-WindowsCapability -Online -Name "Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0"
    runas /netonly /user:hacked.local\administrator powershell
    Import-Module ActiveDirectory
    Import-Module GroupPolicy

.PARAMETER DomainController
    The domain controller to connect to. If not specified, the script will attempt to auto-detect an available domain controller.

.PARAMETER PauseDuration
    The duration in seconds to pause between sections. Default is 5 seconds.

.PARAMETER ReportPath
    The file path where the HTML report will be saved. Default is 'ADSecurityReport.html' in the current directory.

.EXAMPLE
    .\ADSecurityCheck.ps1 -DomainController "DC01.contoso.com" -PauseDuration 5 -ReportPath "C:\Reports\ADSecurityReport.html"
#>

[CmdletBinding()]
param(
    [string]$DomainController = $(Try { (Get-ADDomainController -Discover -Service "PrimaryDC").Name } Catch { Write-Warning "Unable to auto-detect domain controller. Please specify using -DomainController."; exit }),
    [int]$PauseDuration = 5,
    [string]$ReportPath = ".\ADSecurityReport.html"
)

# Ensure the ActiveDirectory module is available
if (-not (Get-Module -Name ActiveDirectory)) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    } catch {
        Write-Host "Failed to import ActiveDirectory module. Please ensure it is installed." -ForegroundColor Red
        exit
    }
}

function Write-SectionHeader {
    param (
        [string]$Header
    )
    Write-Host ""
    Write-Host "======================================" -ForegroundColor Green
    Write-Host "  $Header  " -ForegroundColor White
    Write-Host "======================================" -ForegroundColor Green
}

function Pause-Script {
    param (
        [int]$Seconds = $PauseDuration
    )
    Start-Sleep -Seconds $Seconds
}

# Initialize a collection for the report sections
$ReportSections = @()

# Start of the AD Checks

# Domain and Forest Functional Level
Write-SectionHeader "Retrieving Domain and Forest Functional Level"

$domainInfo = @{
    Section = "Domain and Forest Functional Level"
    Results = @()
}

try {
    $domain = Get-ADDomain -Server $DomainController
    $forest = Get-ADForest -Server $DomainController

    $domainInfo.Results += @{
        DomainFunctionalLevel = $domain.DomainMode
        ForestFunctionalLevel = $forest.ForestMode
    }

    Write-Host "Domain Functional Level: $($domain.DomainMode)" -ForegroundColor Yellow
    Write-Host "Forest Functional Level: $($forest.ForestMode)" -ForegroundColor Yellow
} catch {
    $domainInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error retrieving domain and forest information: $_" -ForegroundColor Red
}

$ReportSections += $domainInfo
Pause-Script

# Active Directory Trusts
Write-SectionHeader "Checking Active Directory Trusts"

$trustInfo = @{
    Section = "Active Directory Trusts"
    Results = @()
}

try {
    $trusts = Get-ADTrust -Filter * -Server $DomainController
    if ($trusts) {
        foreach ($trust in $trusts) {
            $trustInfo.Results += @{
                Name = $trust.Name
                TrustDirection = $trust.TrustDirection
                TrustType = $trust.TrustType
            }
            Write-Host "Trust Name: $($trust.Name), Trust Direction: $($trust.TrustDirection), Trust Type: $($trust.TrustType)" -ForegroundColor Yellow
        }
    } else {
        $trustInfo.Results += @{
            Message = "No Active Directory trusts found."
        }
        Write-Host "No Active Directory trusts found." -ForegroundColor Yellow
    }
} catch {
    $trustInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error retrieving Active Directory trusts: $_" -ForegroundColor Red
}

$ReportSections += $trustInfo
Pause-Script

# Domain Controller OS Versions
Write-SectionHeader "Retrieving Domain Controller OS Versions"

$dcOsInfo = @{
    Section = "Domain Controller OS Versions"
    Results = @()
}

try {
    $dcOU = "CN=Domain Controllers," + (Get-ADDomain -Server $DomainController).DistinguishedName
    $domainControllers = Get-ADComputer -Filter * -SearchBase $dcOU -Properties OperatingSystem, OperatingSystemVersion -Server $DomainController
    foreach ($dc in $domainControllers) {
        $dcOsInfo.Results += @{
            Name = $dc.Name
            OperatingSystem = $dc.OperatingSystem
            OperatingSystemVersion = $dc.OperatingSystemVersion
        }
        Write-Host "Domain Controller $($dc.Name) is running $($dc.OperatingSystem) version $($dc.OperatingSystemVersion)" -ForegroundColor Yellow
    }
} catch {
    $dcOsInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error retrieving domain controller OS versions: $_" -ForegroundColor Red
}

$ReportSections += $dcOsInfo
Pause-Script

# Computer OS Versions
Write-SectionHeader "Retrieving Computer OS Versions"

$computerOsInfo = @{
    Section = "Computer OS Versions"
    Results = @()
}

$obsoleteOperatingSystems = @(
    "Windows Server 2003",
    "Windows Server 2008",
    "Windows Server 2008 R2",
    "Windows Server 2012",
    "Windows Server 2012 R2",
    "Windows 7",
    "Windows 8.1"
)

try {
    $computers = Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion -Server $DomainController
    foreach ($computer in $computers) {
        $isObsolete = $false
        if ($computer.OperatingSystem -and ($computer.OperatingSystem -in $obsoleteOperatingSystems)) {
            $isObsolete = $true
            Write-Host "Computer $($computer.Name) is running an obsolete OS: $($computer.OperatingSystem) version $($computer.OperatingSystemVersion)" -ForegroundColor Red
        } else {
            Write-Host "Computer $($computer.Name) is running $($computer.OperatingSystem) version $($computer.OperatingSystemVersion)" -ForegroundColor Yellow
        }

        $computerOsInfo.Results += @{
            Name = $computer.Name
            OperatingSystem = $computer.OperatingSystem
            OperatingSystemVersion = $computer.OperatingSystemVersion
            IsObsolete = $isObsolete
        }
    }
} catch {
    $computerOsInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error retrieving computer OS versions: $_" -ForegroundColor Red
}

$ReportSections += $computerOsInfo
Pause-Script

# Domain and Enterprise Administrators
Write-SectionHeader "Retrieving Domain and Enterprise Administrators"

$adminInfo = @{
    Section = "Domain and Enterprise Administrators"
    Results = @()
}

try {
    $domainSID = (Get-ADDomain -Server $DomainController).DomainSID
    $domainAdminsSID = "$domainSID-512"
    $enterpriseAdminsSID = "$domainSID-519"

    $domainAdminsGroup = Get-ADGroup -Identity $domainAdminsSID -Server $DomainController
    $domainAdmins = Get-ADGroupMember -Identity $domainAdminsGroup -Recursive -Server $DomainController

    Write-Host "Domain Administrators:" -ForegroundColor Yellow
    foreach ($admin in $domainAdmins) {
        Write-Output "$($admin.SamAccountName)"
        $adminInfo.Results += @{
            Group = "Domain Admins"
            SamAccountName = $admin.SamAccountName
        }
    }
    Write-Host "Total number of Domain Administrators: $($domainAdmins.Count)" -ForegroundColor Yellow

    $enterpriseAdminsGroup = Get-ADGroup -Identity $enterpriseAdminsSID -Server $DomainController
    $enterpriseAdmins = Get-ADGroupMember -Identity $enterpriseAdminsGroup -Recursive -Server $DomainController

    Write-Host "Enterprise Administrators:" -ForegroundColor Yellow
    foreach ($admin in $enterpriseAdmins) {
        Write-Output "$($admin.SamAccountName)"
        $adminInfo.Results += @{
            Group = "Enterprise Admins"
            SamAccountName = $admin.SamAccountName
        }
    }
    Write-Host "Total number of Enterprise Administrators: $($enterpriseAdmins.Count)" -ForegroundColor Yellow

} catch {
    $adminInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error retrieving Domain and Enterprise Administrators: $_" -ForegroundColor Red
}

$ReportSections += $adminInfo
Pause-Script

# Schema Admins Group Check
Write-SectionHeader "Checking Schema Admins Group"

$schemaAdminInfo = @{
    Section = "Schema Admins Group"
    Results = @()
}

try {
    $schemaAdminsSID = "$domainSID-518"
    $schemaAdminsGroup = Get-ADGroup -Identity $schemaAdminsSID -Server $DomainController
    $schemaAdmins = Get-ADGroupMember -Identity $schemaAdminsGroup -Server $DomainController
    if ($schemaAdmins) {
        Write-Host "WARNING: 'Schema Admins' group is not empty. Current members:" -ForegroundColor Red
        foreach ($admin in $schemaAdmins) {
            Write-Host "Name: $($admin.Name), SID: $($admin.SID)" -ForegroundColor Yellow
            $schemaAdminInfo.Results += @{
                Name = $admin.Name
                SID = $admin.SID
            }
        }
    } else {
        $schemaAdminInfo.Results += @{
            Message = "'Schema Admins' group is empty."
        }
        Write-Host "'Schema Admins' group is empty." -ForegroundColor Yellow
    }
} catch {
    $schemaAdminInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking 'Schema Admins' group: $_" -ForegroundColor Red
}

$ReportSections += $schemaAdminInfo
Pause-Script

# Users and Groups with 'admin' in Name
Write-SectionHeader "Checking All Users and Groups with 'admin' in Name"

$adminNameInfo = @{
    Section = "Users and Groups with 'admin' in Name"
    Results = @()
}

try {
    $adminUsers = Get-ADUser -Filter { Name -like '*admin*' } -Server $DomainController | Select-Object Name, SamAccountName
    $adminGroups = Get-ADGroup -Filter { Name -like '*admin*' } -Server $DomainController | Select-Object Name

    Write-Host "`nUsers with 'admin' in name:" -ForegroundColor Yellow
    foreach ($user in $adminUsers) {
        Write-Host $user.Name
        $adminNameInfo.Results += @{
            Type = "User"
            Name = $user.Name
            SamAccountName = $user.SamAccountName
        }
    }

    Write-Host "`nGroups with 'admin' in name:" -ForegroundColor Yellow
    foreach ($group in $adminGroups) {
        Write-Host $group.Name
        $adminNameInfo.Results += @{
            Type = "Group"
            Name = $group.Name
        }
    }
} catch {
    $adminNameInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error retrieving users and groups with 'admin' in name: $_" -ForegroundColor Red
}

$ReportSections += $adminNameInfo
Pause-Script

# Protected Users Group Check
Write-SectionHeader "Checking if all privileged accounts are in the 'Protected Users' group"

$protectedUsersInfo = @{
    Section = "Protected Users Group Check"
    Results = @()
}

try {
    $protectedUsersGroup = Get-ADGroup -Identity "Protected Users" -Server $DomainController
    $protectedUsers = Get-ADGroupMember -Identity $protectedUsersGroup -Recursive -Server $DomainController
    $protectedUserSamAccountNames = $protectedUsers | Select-Object -ExpandProperty SamAccountName

    Write-Host "`nProtected Users:" -ForegroundColor Yellow
    foreach ($user in $protectedUsers) {
        Write-Host $user.Name
        $protectedUsersInfo.Results += @{
            Name = $user.Name
            SamAccountName = $user.SamAccountName
        }
    }

    foreach ($admin in $domainAdmins) {
        if ($admin.SamAccountName -notin $protectedUserSamAccountNames) {
            $protectedUsersInfo.Results += @{
                AdminAccount = $admin.SamAccountName
                InProtectedUsers = $false
            }
            Write-Output "Domain Administrator $($admin.SamAccountName) is not in the 'Protected Users' group"
        }
    }
    foreach ($admin in $enterpriseAdmins) {
        if ($admin.SamAccountName -notin $protectedUserSamAccountNames) {
            $protectedUsersInfo.Results += @{
                AdminAccount = $admin.SamAccountName
                InProtectedUsers = $false
            }
            Write-Output "Enterprise Administrator $($admin.SamAccountName) is not in the 'Protected Users' group"
        }
    }
} catch {
    $protectedUsersInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking 'Protected Users' group: $_" -ForegroundColor Red
}

$ReportSections += $protectedUsersInfo
Pause-Script

# AS-REP Roasting Check
Write-SectionHeader "Checking for users vulnerable to AS-REP Roasting"

$asrepRoastingInfo = @{
    Section = "Users Vulnerable to AS-REP Roasting"
    Results = @()
}

try {
    $asrepUsers = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true -and Enabled -eq $true } -Properties DoesNotRequirePreAuth, SamAccountName -Server $DomainController
    foreach ($user in $asrepUsers) {
        Write-Host "User $($user.SamAccountName) is vulnerable to AS-REP Roasting" -ForegroundColor Red
        $asrepRoastingInfo.Results += @{
            SamAccountName = $user.SamAccountName
        }
    }
} catch {
    $asrepRoastingInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking for AS-REP Roasting vulnerable users: $_" -ForegroundColor Red
}

$ReportSections += $asrepRoastingInfo
Pause-Script

# Kerberoastable Users Check
Write-SectionHeader "Checking for potential Kerberoastable users"

$kerberoastInfo = @{
    Section = "Potential Kerberoastable Users"
    Results = @()
}

try {
    $kerberoastUsers = Get-ADUser -Filter { ServicePrincipalName -ne "$null" -and Enabled -eq $true } -Properties ServicePrincipalName, SamAccountName -Server $DomainController
    foreach ($user in $kerberoastUsers) {
        Write-Host "User $($user.SamAccountName) may be Kerberoastable" -ForegroundColor Red
        $kerberoastInfo.Results += @{
            SamAccountName = $user.SamAccountName
            ServicePrincipalName = $user.ServicePrincipalName
        }
    }
} catch {
    $kerberoastInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking for Kerberoastable users: $_" -ForegroundColor Red
}

$ReportSections += $kerberoastInfo
Pause-Script

# Password Never Expires Check
Write-SectionHeader "Checking for active users with 'Password Never Expires' set"

$passwordNeverExpiresInfo = @{
    Section = "Users with 'Password Never Expires' Set"
    Results = @()
}

try {
    $passwordNeverExpiresUsers = Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } -Properties PasswordNeverExpires, SamAccountName, Enabled -Server $DomainController
    foreach ($user in $passwordNeverExpiresUsers) {
        Write-Host "Active user $($user.SamAccountName) has 'Password Never Expires' set" -ForegroundColor Red
        $passwordNeverExpiresInfo.Results += @{
            SamAccountName = $user.SamAccountName
            PasswordNeverExpires = $user.PasswordNeverExpires
            Enabled = $user.Enabled
        }
    }
} catch {
    $passwordNeverExpiresInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking for users with 'Password Never Expires': $_" -ForegroundColor Red
}

$ReportSections += $passwordNeverExpiresInfo
Pause-Script

# Inactive Users Check
Write-SectionHeader "Checking for inactive users (180 days without login)"

$inactiveUsersInfo = @{
    Section = "Inactive Users (180+ Days)"
    Results = @()
}

try {
    $dateCutoff = (Get-Date).AddDays(-180)
    $inactiveUsers = Get-ADUser -Filter { LastLogonDate -lt $dateCutoff -and Enabled -eq $true } -Properties LastLogonDate, SamAccountName, Enabled -Server $DomainController
    foreach ($user in $inactiveUsers) {
        Write-Output "Active user $($user.SamAccountName) has been inactive since $($user.LastLogonDate)"
        $inactiveUsersInfo.Results += @{
            SamAccountName = $user.SamAccountName
            LastLogonDate = $user.LastLogonDate
        }
    }
} catch {
    $inactiveUsersInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking for inactive users: $_" -ForegroundColor Red
}

$ReportSections += $inactiveUsersInfo
Pause-Script

# Disabled Users Check
Write-SectionHeader "Checking for disabled users"

$disabledUsersInfo = @{
    Section = "Disabled Users"
    Results = @()
}

try {
    $disabledUsers = Get-ADUser -Filter { Enabled -eq $false } -Properties Enabled, SamAccountName -Server $DomainController
    foreach ($user in $disabledUsers) {
        Write-Output "User $($user.SamAccountName) is disabled"
        $disabledUsersInfo.Results += @{
            SamAccountName = $user.SamAccountName
        }
    }
} catch {
    $disabledUsersInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking for disabled users: $_" -ForegroundColor Red
}

$ReportSections += $disabledUsersInfo
Pause-Script

# Locked Out Users Check
Write-SectionHeader "Checking for locked out users"

$lockedOutUsersInfo = @{
    Section = "Locked Out Users"
    Results = @()
}

try {
    $lockedOutUsers = Search-ADAccount -LockedOut -Server $DomainController
    if ($lockedOutUsers) {
        Write-Host "Locked Out Users:" -ForegroundColor Yellow
        foreach ($user in $lockedOutUsers) {
            Write-Output "$($user.SamAccountName)"
            $lockedOutUsersInfo.Results += @{
                SamAccountName = $user.SamAccountName
            }
        }
        Write-Host "Total number of Locked Out Users: $($lockedOutUsers.Count)" -ForegroundColor Yellow
    } else {
        $lockedOutUsersInfo.Results += @{
            Message = "No locked out users found."
        }
        Write-Host "No locked out users found." -ForegroundColor Yellow
    }
} catch {
    $lockedOutUsersInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking for locked out users: $_" -ForegroundColor Red
}

$ReportSections += $lockedOutUsersInfo
Pause-Script

# Users Created in Last 7 Days Check
Write-SectionHeader "Users created in the last 7 days"

$newUsersInfo = @{
    Section = "Users Created in Last 7 Days"
    Results = @()
}

try {
    $date7DaysAgo = (Get-Date).AddDays(-7)
    $usersCreatedLast7Days = Get-ADUser -Filter { WhenCreated -ge $date7DaysAgo } -Server $DomainController
    foreach ($user in $usersCreatedLast7Days) {
        Write-Output "User $($user.SamAccountName) was created within the last 7 days"
        $newUsersInfo.Results += @{
            SamAccountName = $user.SamAccountName
            WhenCreated = $user.WhenCreated
        }
    }
} catch {
    $newUsersInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking for recently created users: $_" -ForegroundColor Red
}

$ReportSections += $newUsersInfo
Pause-Script

# No Password Required Check
Write-SectionHeader "Checking for users with 'No Password Required' flag set"

$noPasswordRequiredInfo = @{
    Section = "Users with 'No Password Required' Flag Set"
    Results = @()
}

try {
    $noPasswordRequiredUsers = Get-ADUser -Filter { PasswordNotRequired -eq $true } -Properties PasswordNotRequired, SamAccountName -Server $DomainController
    foreach ($user in $noPasswordRequiredUsers) {
        Write-Host "User $($user.SamAccountName) has 'No Password Required' flag set" -ForegroundColor Red
        $noPasswordRequiredInfo.Results += @{
            SamAccountName = $user.SamAccountName
            PasswordNotRequired = $user.PasswordNotRequired
        }
    }
} catch {
    $noPasswordRequiredInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking for users with 'No Password Required' flag: $_" -ForegroundColor Red
}

$ReportSections += $noPasswordRequiredInfo
Pause-Script

# Password Policy Check
Write-SectionHeader "Checking Password Policy"

$passwordPolicyInfo = @{
    Section = "Password Policy"
    Results = @()
}

try {
    $passwordPolicy = Get-ADDefaultDomainPasswordPolicy -Server $DomainController

    $policyDetails = @{
        MinPasswordLength = $passwordPolicy.MinPasswordLength
        ComplexityEnabled = $passwordPolicy.ComplexityEnabled
        MaxPasswordAgeDays = $passwordPolicy.MaxPasswordAge.Days
    }

    if ($passwordPolicy.MinPasswordLength -lt 8) {
        $policyDetails.MinPasswordLengthStatus = "Weak"
        Write-Host "The Password Policy allows passwords with less than 8 characters. This represents a high security risk." -ForegroundColor Red
    } else {
        $policyDetails.MinPasswordLengthStatus = "Strong"
        Write-Host "The Password Policy requires a minimum password length of $($passwordPolicy.MinPasswordLength) characters." -ForegroundColor Yellow
    }

    if ($passwordPolicy.ComplexityEnabled) {
        $policyDetails.ComplexityStatus = "Enabled"
        Write-Host "The Password Policy enforces password complexity." -ForegroundColor Yellow
    } else {
        $policyDetails.ComplexityStatus = "Disabled"
        Write-Host "The Password Policy does not enforce password complexity. Consider enabling this for stronger passwords." -ForegroundColor Red
    }

    if ($passwordPolicy.MaxPasswordAge -eq ([TimeSpan]::MaxValue)) {
        $policyDetails.MaxPasswordAgeStatus = "Not Set"
        Write-Host "The Password Policy does not specify a maximum password age." -ForegroundColor Red
    } else {
        $policyDetails.MaxPasswordAgeStatus = "Set"
        Write-Host "The Password Policy requires passwords to be changed every $($passwordPolicy.MaxPasswordAge.Days) days." -ForegroundColor Yellow
    }

    $passwordPolicyInfo.Results += $policyDetails
} catch {
    $passwordPolicyInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error retrieving password policy: $_" -ForegroundColor Red
}

$ReportSections += $passwordPolicyInfo
Pause-Script

# Service Accounts Operating As User Accounts Check
Write-SectionHeader "Checking Service Accounts Operating As User Accounts"

$serviceAccountsInfo = @{
    Section = "Service Accounts Operating As User Accounts"
    Results = @()
}

try {
    $serviceAccounts = Get-ADUser -Filter { (Name -like "*service*") -or (Name -like "*svc*") } -Properties PasswordLastSet -Server $DomainController | Select-Object Name, PasswordLastSet
    foreach ($account in $serviceAccounts) {
        Write-Host "Service Account: $($account.Name), Password Last Set: $($account.PasswordLastSet)" -ForegroundColor Yellow
        $serviceAccountsInfo.Results += @{
            Name = $account.Name
            PasswordLastSet = $account.PasswordLastSet
        }
    }
} catch {
    $serviceAccountsInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking service accounts: $_" -ForegroundColor Red
}

$ReportSections += $serviceAccountsInfo
Pause-Script

# Backup Accounts Check
Write-SectionHeader "Checking Backup Accounts"

$backupAccountsInfo = @{
    Section = "Backup Accounts"
    Results = @()
}

try {
    $backupAccounts = Get-ADUser -Filter { (Name -like "*backup*") -or (Name -like "*bkp*") } -Properties PasswordLastSet -Server $DomainController | Select-Object Name, PasswordLastSet
    foreach ($account in $backupAccounts) {
        Write-Host "Backup Account: $($account.Name), Password Last Set: $($account.PasswordLastSet)" -ForegroundColor Yellow
        $backupAccountsInfo.Results += @{
            Name = $account.Name
            PasswordLastSet = $account.PasswordLastSet
        }
    }
} catch {
    $backupAccountsInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking backup accounts: $_" -ForegroundColor Red
}

$ReportSections += $backupAccountsInfo
Pause-Script

# Accounts With Admin Count Set Check
Write-SectionHeader "Checking All Accounts With Admin Count Set"

$adminCountInfo = @{
    Section = "Accounts With Admin Count Set"
    Results = @()
}

try {
    $adminCountAccounts = Get-ADUser -Filter { AdminCount -eq 1 } -Properties PasswordLastSet, AdminCount -Server $DomainController | Select-Object Name, PasswordLastSet, AdminCount
    foreach ($account in $adminCountAccounts) {
        Write-Host "User: $($account.Name), Password Last Set: $($account.PasswordLastSet), AdminCount: $($account.AdminCount)" -ForegroundColor Yellow
        $adminCountInfo.Results += @{
            Name = $account.Name
            PasswordLastSet = $account.PasswordLastSet
            AdminCount = $account.AdminCount
        }
    }
} catch {
    $adminCountInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking accounts with AdminCount set: $_" -ForegroundColor Red
}

$ReportSections += $adminCountInfo
Pause-Script

# Domain Controllers support NTLMv1 and LM Check
Write-SectionHeader "Checking if Domain Controllers support NTLMv1 and LM"

$ntlmSupportInfo = @{
    Section = "Domain Controllers NTLMv1 and LM Support"
    Results = @()
}

try {
    $dcs = Get-ADDomainController -Server $DomainController
    foreach ($dc in $dcs) {
        $cimSession = New-CimSession -ComputerName $dc.HostName
        $lmCompatibilityLevel = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -CimSession $cimSession
        $level = $lmCompatibilityLevel.LmCompatibilityLevel

        $ntlmSupportInfo.Results += @{
            DomainController = $dc.HostName
            LmCompatibilityLevel = $level
        }

        Write-Host "Domain Controller $($dc.HostName) LmCompatibilityLevel: $level" -ForegroundColor Yellow

        Remove-CimSession -CimSession $cimSession
    }
} catch {
    $ntlmSupportInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking NTLMv1 and LM support: $_" -ForegroundColor Red
}

$ReportSections += $ntlmSupportInfo
Pause-Script

# Administrator Accounts Which Can Be Delegated Check
Write-SectionHeader "Checking All Administrator Accounts Which Can Be Delegated"

$delegatableAdminsInfo = @{
    Section = "Administrator Accounts Which Can Be Delegated"
    Results = @()
}

try {
    $adminAccounts = $domainAdmins + $enterpriseAdmins
    foreach ($account in $adminAccounts) {
        $user = Get-ADUser -Identity $account.SamAccountName -Properties AccountNotDelegated -Server $DomainController
        if ($user.AccountNotDelegated -eq $false) {
            Write-Output "Administrator account $($user.SamAccountName) can be delegated."
            $delegatableAdminsInfo.Results += @{
                SamAccountName = $user.SamAccountName
                CanBeDelegated = $true
            }
        }
    }
} catch {
    $delegatableAdminsInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking administrator accounts for delegation: $_" -ForegroundColor Red
}

$ReportSections += $delegatableAdminsInfo
Pause-Script

# Possible Test Accounts Check
Write-SectionHeader "Checking All User Accounts for Possible Test Accounts"

$testAccountsInfo = @{
    Section = "Possible Test Accounts"
    Results = @()
}

try {
    $words = 'test', 'dev', 'demo', 'dummy', 'sandbox', 'delete', 'trial', 'bloggs', 'doe', 'old', 'remove', 'pentest', '1234'
    $allAccounts = Get-ADUser -Filter * -Properties SamAccountName -Server $DomainController
    foreach ($account in $allAccounts) {
        foreach ($word in $words) {
            if ($account.SamAccountName -match $word) {
                Write-Output "Possible Test Account: $($account.SamAccountName)"
                $testAccountsInfo.Results += @{
                    SamAccountName = $account.SamAccountName
                }
                break
            }
        }
    }
} catch {
    $testAccountsInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking for possible test accounts: $_" -ForegroundColor Red
}

$ReportSections += $testAccountsInfo
Pause-Script

# OUs for Delegations to 'Everyone' or 'Authenticated Users' Check
Write-SectionHeader "Checking All OUs for Delegations to 'Everyone' or 'Authenticated Users'"

$ouDelegationsInfo = @{
    Section = "OUs with Delegations to 'Everyone' or 'Authenticated Users'"
    Results = @()
}

try {
    $OUs = Get-ADOrganizationalUnit -Filter * -Properties nTSecurityDescriptor -Server $DomainController
    foreach ($OU in $OUs) {
        $acl = $OU.nTSecurityDescriptor
        foreach ($access in $acl.Access) {
            if ($access.IdentityReference -match 'S-1-1-0|S-1-5-11') {
                Write-Host "WARNING: OU '$($OU.Name)' has delegation for '$($access.IdentityReference)'." -ForegroundColor Red
                $ouDelegationsInfo.Results += @{
                    OUName = $OU.Name
                    IdentityReference = $access.IdentityReference
                }
            }
        }
    }
} catch {
    $ouDelegationsInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking OUs for delegations: $_" -ForegroundColor Red
}

$ReportSections += $ouDelegationsInfo
Pause-Script

# krbtgt Password Last Set Check
Write-SectionHeader "Checking krbtgt Password Last Set"

$krbtgtInfo = @{
    Section = "krbtgt Password Last Set"
    Results = @()
}

try {
    $krbtgt = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet -Server $DomainController
    $now = Get-Date
    $monthsSinceLastSet = (($now - $krbtgt.PasswordLastSet).Days) / 30
    $status = if ($monthsSinceLastSet -gt 6) { "Password older than 6 months" } else { "Password recently changed" }
    Write-Host "krbtgt password was last set on $($krbtgt.PasswordLastSet) ($status)." -ForegroundColor Yellow

    $krbtgtInfo.Results += @{
        PasswordLastSet = $krbtgt.PasswordLastSet
        Status = $status
    }
} catch {
    $krbtgtInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking krbtgt password last set: $_" -ForegroundColor Red
}

$ReportSections += $krbtgtInfo
Pause-Script

# Anonymous LDAP Check
Write-SectionHeader "Checking Anonymous LDAP"

$anonymousLDAPInfo = @{
    Section = "Anonymous LDAP"
    Results = @()
}

try {
    $rootDSE = Get-ADRootDSE -Server $DomainController
    $domainPolicy = Get-ADObject -Identity ($rootDSE.defaultNamingContext) -Properties dSHeuristics -Server $DomainController
    if ($domainPolicy.dSHeuristics -eq $null) {
        $status = "Disabled"
        Write-Host "Anonymous LDAP is DISABLED." -ForegroundColor Yellow
    } elseif ($domainPolicy.dSHeuristics.Substring(2,1) -eq "2") {
        $status = "Disabled"
        Write-Host "Anonymous LDAP is DISABLED." -ForegroundColor Yellow
    } else {
        $status = "Enabled"
        Write-Host "WARNING: Anonymous LDAP is ENABLED." -ForegroundColor Red
    }

    $anonymousLDAPInfo.Results += @{
        Status = $status
    }
} catch {
    $anonymousLDAPInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking Anonymous LDAP: $_" -ForegroundColor Red
}

$ReportSections += $anonymousLDAPInfo
Pause-Script

# Windows 2000 Pre-Authentication Accounts Check
Write-SectionHeader "Checking Windows 2000 Pre-Authentication Accounts"

$preWin2000Info = @{
    Section = "Windows 2000 Pre-Authentication Accounts"
    Results = @()
}

try {
    $preWin2000Group = Get-ADGroup -Identity "Pre-Windows 2000 Compatible Access" -Server $DomainController
    $preWin2000Members = Get-ADGroupMember -Identity $preWin2000Group -Server $DomainController
    if ($preWin2000Members) {
        foreach ($member in $preWin2000Members) {
            Write-Output "Member: $($member.Name) (Type: $($member.objectClass))"
            $preWin2000Info.Results += @{
                Name = $member.Name
                ObjectClass = $member.objectClass
            }
        }
    } else {
        $preWin2000Info.Results += @{
            Message = "No members found in the 'Pre-Windows 2000 Compatible Access' group."
        }
        Write-Host "No members found in the 'Pre-Windows 2000 Compatible Access' group." -ForegroundColor Yellow
    }
} catch {
    $preWin2000Info.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking 'Pre-Windows 2000 Compatible Access' group: $_" -ForegroundColor Red
}

$ReportSections += $preWin2000Info
Pause-Script

# DNSAdmins Group Members
Write-SectionHeader "DNSAdmins Group Members"

$dnsAdminsInfo = @{
    Section = "DNSAdmins Group Members"
    Results = @()
}

try {
    $dnsAdmins = Get-ADGroupMember -Identity "DNSAdmins" -Server $DomainController | Select-Object Name, SamAccountName | Sort-Object Name
    if ($dnsAdmins) {
        foreach ($member in $dnsAdmins) {
            Write-Host "Member: $($member.Name) ($($member.SamAccountName))" -ForegroundColor Yellow
            $dnsAdminsInfo.Results += @{
                Name = $member.Name
                SamAccountName = $member.SamAccountName
            }
        }
    } else {
        $dnsAdminsInfo.Results += @{
            Message = "No members found in the 'DNSAdmins' group."
        }
        Write-Host "No members found in the 'DNSAdmins' group." -ForegroundColor Yellow
    }
} catch {
    $dnsAdminsInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking 'DNSAdmins' group: $_" -ForegroundColor Red
}

$ReportSections += $dnsAdminsInfo
Pause-Script

# Backup Operators Group Members
Write-SectionHeader "Backup Operators Group Members"

$backupOperatorsInfo = @{
    Section = "Backup Operators Group Members"
    Results = @()
}

try {
    $backupOperators = Get-ADGroupMember -Identity "Backup Operators" -Server $DomainController | Select-Object Name, SamAccountName | Sort-Object Name
    if ($backupOperators) {
        foreach ($member in $backupOperators) {
            Write-Host "Member: $($member.Name) ($($member.SamAccountName))" -ForegroundColor Yellow
            $backupOperatorsInfo.Results += @{
                Name = $member.Name
                SamAccountName = $member.SamAccountName
            }
        }
    } else {
        $backupOperatorsInfo.Results += @{
            Message = "No members found in the 'Backup Operators' group."
        }
        Write-Host "No members found in the 'Backup Operators' group." -ForegroundColor Yellow
    }
} catch {
    $backupOperatorsInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking 'Backup Operators' group: $_" -ForegroundColor Red
}

$ReportSections += $backupOperatorsInfo
Pause-Script

# AD Administrator Account Renamed Check
Write-SectionHeader "Checking if AD Administrator Account Has Been Renamed"

$adminAccountRenameInfo = @{
    Section = "AD Administrator Account Renamed Check"
    Results = @()
}

try {
    $domainSID = (Get-ADDomain -Server $DomainController).DomainSID
    $adminSID = "$domainSID-500"
    $adminAccount = Get-ADUser -Filter { SID -eq $adminSID } -Server $DomainController
    if ($adminAccount.SamAccountName -eq "Administrator") {
        $status = "Not Renamed"
        Write-Host "The AD administrator account has not been renamed." -ForegroundColor Yellow
    } else {
        $status = "Renamed to $($adminAccount.SamAccountName)"
        Write-Host "The AD administrator account has been renamed to $($adminAccount.SamAccountName)." -ForegroundColor Yellow
    }

    $adminAccountRenameInfo.Results += @{
        AdminAccountName = $adminAccount.SamAccountName
        Status = $status
    }
} catch {
    $adminAccountRenameInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking if AD administrator account has been renamed: $_" -ForegroundColor Red
}

$ReportSections += $adminAccountRenameInfo
Pause-Script

# Checking if the Active Directory Recycle Bin has been enabled
Write-SectionHeader "Checking if Recycle Bin Has Been Enabled"

$recycleBinInfo = @{
    Section = "Active Directory Recycle Bin Status"
    Results = @()
}

try {
    $forest = Get-ADForest -Server $DomainController
    $recycleBinFeature = Get-ADOptionalFeature -Filter { Name -like "Recycle Bin Feature" } -Server $DomainController
    if ($recycleBinFeature.EnabledScopes -ne $null) {
        $status = "Enabled"
        Write-Host "The AD Recycle Bin is enabled." -ForegroundColor Yellow
    } else {
        $status = "Disabled"
        Write-Host "The AD Recycle Bin is not enabled." -ForegroundColor Yellow
    }

    $recycleBinInfo.Results += @{
        Status = $status
    }
} catch {
    $recycleBinInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Failed to determine the AD Recycle Bin status: $_" -ForegroundColor Red
}

$ReportSections += $recycleBinInfo
Pause-Script

# SQL Server Enumeration via Active Directory PowerShell
Write-SectionHeader "SQL Server Enumeration via Active Directory PowerShell"

$sqlServersInfo = @{
    Section = "SQL Server Enumeration"
    Results = @()
}

try {
    $sqlServers = Get-ADObject -Filter 'ObjectClass -eq "serviceConnectionPoint"' -Properties keywords -Server $DomainController |
        Where-Object { $_.keywords -like "*MSSQL*" } |
        ForEach-Object { $_.DistinguishedName }
    if ($sqlServers) {
        Write-Host "SQL Servers found:" -ForegroundColor Yellow
        foreach ($sqlServer in $sqlServers) {
            Write-Host $sqlServer
            $sqlServersInfo.Results += @{
                DistinguishedName = $sqlServer
            }
        }
    } else {
        $sqlServersInfo.Results += @{
            Message = "No SQL Servers found."
        }
        Write-Host "No SQL Servers found." -ForegroundColor Yellow
    }
} catch {
    $sqlServersInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error enumerating SQL Servers: $_" -ForegroundColor Red
}

$ReportSections += $sqlServersInfo
Pause-Script

# Active Directory Group Enumeration for Domain Users
Write-SectionHeader "Active Directory Group Enumeration for Domain Users"

$domainUsersGroupInfo = @{
    Section = "Groups Containing 'Domain Users'"
    Results = @()
}

try {
    $domainUsersGroup = Get-ADGroup -Identity "Domain Users" -Properties MemberOf -Server $DomainController
    $memberOf = $domainUsersGroup.MemberOf
    if ($memberOf) {
        foreach ($groupDN in $memberOf) {
            $groupInfo = Get-ADGroup -Identity $groupDN -Server $DomainController
            Write-Host "Group Name: $($groupInfo.Name)" -ForegroundColor Yellow
            $domainUsersGroupInfo.Results += @{
                GroupName = $groupInfo.Name
            }
        }
    } else {
        $domainUsersGroupInfo.Results += @{
            Message = "'Domain Users' group is not a member of any other groups."
        }
        Write-Host "'Domain Users' group is not a member of any other groups." -ForegroundColor Yellow
    }
} catch {
    $domainUsersGroupInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error enumerating groups for 'Domain Users': $_" -ForegroundColor Red
}

$ReportSections += $domainUsersGroupInfo
Pause-Script

# Active Directory Enumeration for ms-DS-MachineAccountQuota
Write-SectionHeader "Active Directory Enumeration for ms-DS-MachineAccountQuota"

$maQuotaInfo = @{
    Section = "ms-DS-MachineAccountQuota"
    Results = @()
}

try {
    $domainDN = (Get-ADDomain -Server $DomainController).DistinguishedName
    $domainRoot = Get-ADObject -Identity $domainDN -Properties "ms-DS-MachineAccountQuota" -Server $DomainController
    $quota = $domainRoot.'ms-DS-MachineAccountQuota'
    Write-Host "The ms-DS-MachineAccountQuota for the domain is: $quota" -ForegroundColor Yellow
    $maQuotaInfo.Results += @{
        MachineAccountQuota = $quota
    }
} catch {
    $maQuotaInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error retrieving ms-DS-MachineAccountQuota: $_" -ForegroundColor Red
}

$ReportSections += $maQuotaInfo
Pause-Script

# Checking for computers Trusted for Delegation and part of Domain Computers group
Write-SectionHeader "Checking for Computers Trusted for Delegation and Part of Domain Computers Group"

$trustedComputersInfo = @{
    Section = "Computers Trusted for Delegation in 'Domain Computers' Group"
    Results = @()
}

try {
    $trustedComputers = Get-ADComputer -Filter { TrustedForDelegation -eq $true -and PrimaryGroupID -eq 515 } -Properties TrustedForDelegation, ServicePrincipalName, Description -Server $DomainController
    foreach ($computer in $trustedComputers) {
        Write-Host "Computer $($computer.Name) is Trusted for Delegation and is part of Domain Computers group" -ForegroundColor Red
        $trustedComputersInfo.Results += @{
            ComputerName = $computer.Name
        }
    }
} catch {
    $trustedComputersInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking for computers trusted for delegation: $_" -ForegroundColor Red
}

$ReportSections += $trustedComputersInfo
Pause-Script

# BEGIN ADDITIONAL CHECKS

# Accounts with Expired Passwords but Still Active
Write-SectionHeader "Checking for Accounts with Expired Passwords but Still Active"

$expiredPasswordsInfo = @{
    Section = "Accounts with Expired Passwords but Still Active"
    Results = @()
}

try {
    $expiredAccounts = Get-ADUser -Filter { PasswordExpired -eq $true -and Enabled -eq $true } -Properties PasswordExpired, SamAccountName, Enabled -Server $DomainController
    foreach ($user in $expiredAccounts) {
        Write-Output "User $($user.SamAccountName) has an expired password but is still active."
        $expiredPasswordsInfo.Results += @{
            SamAccountName    = $user.SamAccountName
            PasswordExpired   = $user.PasswordExpired
            Enabled           = $user.Enabled
        }
    }
} catch {
    $expiredPasswordsInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking for accounts with expired passwords: $_" -ForegroundColor Red
}

$ReportSections += $expiredPasswordsInfo
Pause-Script

# Check for Duplicate Service Principal Names (SPNs)
Write-SectionHeader "Checking for Duplicate Service Principal Names (SPNs)"

$duplicateSPNsInfo = @{
    Section = "Duplicate Service Principal Names (SPNs)"
    Results = @()
}

try {
    $allSPNs = Get-ADObject -Filter { ServicePrincipalName -ne "$null" } -Properties ServicePrincipalName, SamAccountName -Server $DomainController
    $spnHash = @{}
    foreach ($obj in $allSPNs) {
        foreach ($spn in $obj.ServicePrincipalName) {
            if ($spnHash.ContainsKey($spn)) {
                $duplicateSPNsInfo.Results += @{
                    SPN      = $spn
                    Accounts = "$($spnHash[$spn]), $($obj.SamAccountName)"
                }
                Write-Output "Duplicate SPN found: $spn assigned to $($spnHash[$spn]) and $($obj.SamAccountName)"
            } else {
                $spnHash[$spn] = $obj.SamAccountName
            }
        }
    }
} catch {
    $duplicateSPNsInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking for duplicate SPNs: $_" -ForegroundColor Red
}

$ReportSections += $duplicateSPNsInfo
Pause-Script

# Check for Accounts with SID History
Write-SectionHeader "Checking for Accounts with SID History"

$sidHistoryInfo = @{
    Section = "Accounts with SID History"
    Results = @()
}

try {
    $accountsWithSidHistory = Get-ADUser -Filter { sIDHistory -ne "$null" } -Properties sIDHistory, SamAccountName -Server $DomainController
    foreach ($account in $accountsWithSidHistory) {
        Write-Output "Account $($account.SamAccountName) has SID History."
        $sidHistoryInfo.Results += @{
            SamAccountName = $account.SamAccountName
            SIDHistory     = $account.sIDHistory -join "; "
        }
    }
} catch {
    $sidHistoryInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking for accounts with SID History: $_" -ForegroundColor Red
}

$ReportSections += $sidHistoryInfo
Pause-Script

# Check for Accounts with Unconstrained Delegation
Write-SectionHeader "Checking for Accounts with Unconstrained Delegation"

$unconstrainedDelegationInfo = @{
    Section = "Accounts with Unconstrained Delegation"
    Results = @()
}

try {
    $unconstrainedAccounts = Get-ADUser -Filter { TrustedForDelegation -eq $true } -Properties SamAccountName, TrustedForDelegation -Server $DomainController
    foreach ($account in $unconstrainedAccounts) {
        Write-Output "User account $($account.SamAccountName) is trusted for unconstrained delegation."
        $unconstrainedDelegationInfo.Results += @{
            SamAccountName = $account.SamAccountName
            Type           = "User"
        }
    }

    $unconstrainedComputers = Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties DNSHostName, TrustedForDelegation -Server $DomainController
    foreach ($computer in $unconstrainedComputers) {
        Write-Output "Computer account $($computer.DNSHostName) is trusted for unconstrained delegation."
        $unconstrainedDelegationInfo.Results += @{
            SamAccountName = $computer.Name
            DNSHostName    = $computer.DNSHostName
            Type           = "Computer"
        }
    }
} catch {
    $unconstrainedDelegationInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking for unconstrained delegation: $_" -ForegroundColor Red
}

$ReportSections += $unconstrainedDelegationInfo
Pause-Script

# Check for Nested Groups with High Privileges
Write-SectionHeader "Checking for Nested Groups with High Privileges"

$nestedGroupsInfo = @{
    Section = "Nested Groups with High Privileges"
    Results = @()
}

try {
    $highPrivGroups = @("Domain Admins", "Enterprise Admins", "Administrators")
    foreach ($groupName in $highPrivGroups) {
        $group = Get-ADGroup -Identity $groupName -Server $DomainController
        $members = Get-ADGroupMember -Identity $group -Server $DomainController
        foreach ($member in $members) {
            if ($member.objectClass -eq "group") {
                Write-Output "Group $($member.Name) is nested within $groupName."
                $nestedGroupsInfo.Results += @{
                    HighPrivGroup = $groupName
                    NestedGroup   = $member.Name
                }
            }
        }
    }
} catch {
    $nestedGroupsInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking for nested groups with high privileges: $_" -ForegroundColor Red
}

$ReportSections += $nestedGroupsInfo
Pause-Script

# Check for Orphaned GPOs
Write-SectionHeader "Checking for Orphaned Group Policy Objects (GPOs)"

$orphanedGPOsInfo = @{
    Section = "Orphaned Group Policy Objects"
    Results = @()
}

try {
    Import-Module GroupPolicy -ErrorAction Stop
    $allGPOs = Get-GPO -All
    foreach ($gpo in $allGPOs) {
        $links = Get-GPOReport -Guid $gpo.Id -ReportType Xml | Select-Xml -XPath "//LinksTo/SOMLink"
        if ($links.Count -eq 0) {
            Write-Output "GPO $($gpo.DisplayName) is not linked to any site, domain, or OU."
            $orphanedGPOsInfo.Results += @{
                GPOName = $gpo.DisplayName
                GPOId   = $gpo.Id
            }
        }
    }
} catch {
    $orphanedGPOsInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error checking for orphaned GPOs: $_" -ForegroundColor Red
}

$ReportSections += $orphanedGPOsInfo
Pause-Script

# BEGIN AD STRUCTURE VISUALIZATION WITH COLLAPSIBLE TREE

Write-SectionHeader "Collecting Active Directory Structure for Visualization"

$adStructureInfo = @{
    Section = "Active Directory Structure"
    Results = @()
}

try {
    # Function to recursively get OUs and their child OUs
    function Get-ChildOUs {
        param (
            [string]$ParentOU
        )
        $ous = Get-ADOrganizationalUnit -Filter * -SearchBase $ParentOU -Properties Name | Sort-Object Name
        $ouList = @()
        foreach ($ou in $ous) {
            $childOUs = Get-ChildOUs -ParentOU $ou.DistinguishedName
            $users = Get-ADUser -Filter * -SearchBase $ou.DistinguishedName -Properties Name | Sort-Object Name
            $userList = @()
            foreach ($user in $users) {
                $userList += @{
                    Name = $user.Name
                }
            }
            $ouList += @{
                Name = $ou.Name
                Users = $userList
                ChildOUs = $childOUs
            }
        }
        return $ouList
    }

    # Get the root domain
    $rootDomainDN = (Get-ADDomain -Server $DomainController).DistinguishedName
    $rootDomainName = (Get-ADDomain -Server $DomainController).Name

    # Get top-level OUs
    $topLevelOUs = Get-ADOrganizationalUnit -Filter * -SearchBase $rootDomainDN -SearchScope OneLevel -Properties Name | Sort-Object Name
    $adHierarchy = @()

    foreach ($ou in $topLevelOUs) {
        $childOUs = Get-ChildOUs -ParentOU $ou.DistinguishedName
        $users = Get-ADUser -Filter * -SearchBase $ou.DistinguishedName -Properties Name | Sort-Object Name
        $userList = @()
        foreach ($user in $users) {
            $userList += @{
                Name = $user.Name
            }
        }
        $adHierarchy += @{
            Name = $ou.Name
            Users = $userList
            ChildOUs = $childOUs
        }
    }

    # Add the root domain and its top-level OUs to the Results
    $adStructureInfo.Results += @{
        DomainName = $rootDomainName
        OUs = $adHierarchy
    }

    Write-Host "Active Directory structure successfully collected." -ForegroundColor Green
} catch {
    $adStructureInfo.Results += @{
        Error = $_.Exception.Message
    }
    Write-Host "Error collecting Active Directory structure: $_" -ForegroundColor Red
}

$ReportSections += $adStructureInfo
Pause-Script

# END OF AD STRUCTURE VISUALIZATION WITH COLLAPSIBLE TREE



# Generate HTML Report
Write-Host "Generating HTML Report at $ReportPath" -ForegroundColor Green

try {
    $reportDirectory = Split-Path -Path $ReportPath -Parent
    if (-not (Test-Path -Path $reportDirectory)) {
        New-Item -Path $reportDirectory -ItemType Directory -Force | Out-Null
    }

    $htmlContent = @"
<html>
<head>
    <title>Active Directory Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #dddddd; text-align: left; padding: 8px; }
        th { background-color: #f2f2f2; }
        ul { list-style-type: none; margin: 0; padding: 0; }
        li { margin-left: 20px; cursor: pointer; }
        .collapsible::before { content: '\25B6'; display: inline-block; margin-right: 6px; }
        .active::before { content: '\25BC'; }
        .nested { display: none; }
    </style>
</head>
<body>
    <h1>Active Directory Security Report</h1>
    <p>Report generated on: $(Get-Date)</p>
"@

    foreach ($section in $ReportSections) {
        $htmlContent += "<h2>$($section.Section)</h2>"
        if ($section.Results -and $section.Results.Count -gt 0) {
            if ($section.Section -eq "Active Directory Structure") {
                # Special handling for the AD Structure section
                $htmlContent += "<ul>"
                $domainName = $section.Results[0].DomainName
                $htmlContent += "<li class='collapsible'><strong>Domain: $domainName</strong>"
                function Build-OuHtml {
                    param (
                        [array]$OUs
                    )
                    $html = "<ul class='nested'>"
                    foreach ($ou in $OUs) {
                        $html += "<li class='collapsible'><strong>OU: $($ou.Name)</strong>"
                        if ($ou.Users.Count -gt 0) {
                            $html += "<ul class='nested'>"
                            foreach ($user in $ou.Users) {
                                $html += "<li>User: $($user.Name)</li>"
                            }
                            $html += "</ul>"
                        }
                        if ($ou.ChildOUs.Count -gt 0) {
                            $html += Build-OuHtml -OUs $ou.ChildOUs
                        }
                        $html += "</li>"
                    }
                    $html += "</ul>"
                    return $html
                }
                $htmlContent += Build-OuHtml -OUs $section.Results[0].OUs
                $htmlContent += "</li></ul>"
            } else {
                # Existing handling for other sections
                $htmlContent += "<table>"
                $headers = $section.Results[0].Keys
                $htmlContent += "<tr>"
                foreach ($header in $headers) {
                    $htmlContent += "<th>$header</th>"
                }
                $htmlContent += "</tr>"
                foreach ($result in $section.Results) {
                    $htmlContent += "<tr>"
                    foreach ($header in $headers) {
                        $value = $result[$header]
                        if ($value -eq $null) { $value = "" }
                        $htmlContent += "<td>$value</td>"
                    }
                    $htmlContent += "</tr>"
                }
                $htmlContent += "</table>"
            }
        } else {
            $htmlContent += "<p>No data available for this section.</p>"
        }
    }

    # Add JavaScript to handle collapsible functionality
    $htmlContent += @"
<script>
document.addEventListener('DOMContentLoaded', function() {
    var toggler = document.getElementsByClassName('collapsible');
    for (var i = 0; i < toggler.length; i++) {
        toggler[i].addEventListener('click', function(e) {
            e.stopPropagation();
            this.classList.toggle('active');
            var nested = this.nextElementSibling;
            if (nested && nested.classList.contains('nested')) {
                if (nested.style.display === 'block') {
                    nested.style.display = 'none';
                } else {
                    nested.style.display = 'block';
                }
            }
        });
    }
});
</script>
</body>
</html>
"@

    Set-Content -Path $ReportPath -Value $htmlContent -Encoding UTF8

    Write-Host "HTML Report successfully generated at $ReportPath" -ForegroundColor Green
} catch {
    Write-Host "Error generating HTML report: $_" -ForegroundColor Red
}
