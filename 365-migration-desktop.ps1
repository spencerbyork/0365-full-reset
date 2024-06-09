# Function to stop OneDrive process
function Stop-OneDriveProcess {
    Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
}

# Function to remove OneDrive business and business1 account registry entries for all users
function Remove-OneDriveBusinessAccounts {
    # Get all subkeys under HKEY_USERS
    $userSIDs = Get-ChildItem -Path "Registry::HKEY_USERS\"

    foreach ($userSID in $userSIDs) {
        $userBusinessHive = "Registry::HKEY_USERS\$($userSID.PSChildName)\Software\Microsoft\OneDrive\Accounts\Business"
        $userBusiness1Hive = "Registry::HKEY_USERS\$($userSID.PSChildName)\Software\Microsoft\OneDrive\Accounts\Business1"

        if (Test-Path -Path $userBusinessHive) {
            try {
                Remove-Item -Path $userBusinessHive -Recurse -Force -ErrorAction Stop
            } catch {}
        }

        if (Test-Path -Path $userBusiness1Hive) {
            try {
                Remove-Item -Path $userBusiness1Hive -Recurse -Force -ErrorAction Stop
            } catch {}
        }
    }
}

# Call the functions to stop OneDrive and remove business and business1 account registry entries
Stop-OneDriveProcess
Remove-OneDriveBusinessAccounts

# Function to clear cache
function Clear-Cache {
    param (
        [string]$cacheFolder
    )

    Remove-Item -Path $cacheFolder\* -Force -Recurse -ErrorAction SilentlyContinue
}

# Function to clear Teams cache for all users
function Clear-TeamsCacheForAllUsers {
    $userProfiles = Get-WmiObject -Class Win32_UserProfile | Where-Object { $_.Special -eq $false }

    foreach ($profile in $userProfiles) {
        $userProfilePath = $profile.LocalPath
        $newCacheFolder = "$userProfilePath\AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams"
        $classicCacheFolder = "$userProfilePath\AppData\Roaming\Microsoft\Teams"

        try {
            $teamsProcess = Get-Process -Name "MS-Teams" -ErrorAction SilentlyContinue
            if ($teamsProcess -eq $null) {
                $teamsProcess = Get-Process -Name "Teams" -ErrorAction SilentlyContinue
            }

            if ($teamsProcess -ne $null) {
                Stop-Process -Id $teamsProcess.Id -Force
                if ($teamsProcess.Name -eq "MS-Teams") {
                    Clear-Cache -cacheFolder $newCacheFolder
                } else {
                    Clear-Cache -cacheFolder $classicCacheFolder
                }
            } else {
                if (Test-Path -Path $newCacheFolder) {
                    Clear-Cache -cacheFolder $newCacheFolder
                } else {
                    Clear-Cache -cacheFolder $classicCacheFolder
                }
            }
        } catch {}
    }
}

# Call the function to clear Teams cache for all users
Clear-TeamsCacheForAllUsers

# Define constants
$OfficeAppId = "0ff1ce15-a989-479d-af46-f275c6370663"  # Office 2013/2016
$SKUFILTER = "O365" # Removes all licenses that contain O365 in their name

# Clear folder contents
function Clear-Folder {
    param (
        [string]$folderPath
    )
    if (Test-Path -Path $folderPath) {
        Remove-Item -Path $folderPath\* -Force -Recurse -ErrorAction SilentlyContinue
    }
}

# Clear Office licenses
function Clear-OfficeLicenses {
    $licenses = Get-WmiObject -Query "SELECT ID, ApplicationId, PartialProductKey, Description, Name, ProductKeyID FROM SoftwareLicensingProduct WHERE ApplicationId = '$OfficeAppId' AND PartialProductKey <> NULL"
    foreach ($license in $licenses) {
        if ($license.Name -like "*$SKUFILTER*") {
            $license.UninstallProductKey($license.ProductKeyID)
        }
    }
}

# Main cleanup function
function Cleanup-Office {
    Clear-OfficeLicenses

    $userProfilePaths = Get-WmiObject -Class Win32_UserProfile | Where-Object { $_.Special -eq $false }
    foreach ($profile in $userProfilePaths) {
        $userProfilePath = $profile.LocalPath
        Clear-Folder "$userProfilePath\AppData\Local\Microsoft\Office\15.0\Licensing"
        Clear-Folder "$userProfilePath\AppData\Local\Microsoft\Office\16.0\Licensing"
        Clear-Folder "$userProfilePath\AppData\Local\Microsoft\Office\Licenses"
        Clear-Folder "$userProfilePath\AppData\Local\Microsoft\IdentityCache"
        Clear-Folder "$userProfilePath\AppData\Local\Microsoft\OneAuth"
    }

    $registryPaths = @(
        "HKCU:\Software\Microsoft\Office\15.0\Common\Identity",
        "HKCU:\Software\Microsoft\Office\15.0\Common\Roaming\Identities",
        "HKCU:\Software\Microsoft\Office\15.0\Common\Internet\WebServiceCache",
        "HKCU:\Software\Microsoft\Office\15.0\Common\ServicesManagerCache",
        "HKCU:\Software\Microsoft\Office\15.0\Common\Licensing",
        "HKCU:\Software\Microsoft\Office\15.0\Registration",
        "HKCU:\Software\Microsoft\Office\16.0\Common\Identity",
        "HKCU:\Software\Microsoft\Office\16.0\Common\Roaming\Identities",
        "HKCU:\Software\Microsoft\Office\16.0\Common\Internet\WebServiceCache",
        "HKCU:\Software\Microsoft\Office\16.0\Common\ServicesManagerCache",
        "HKCU:\Software\Microsoft\Office\16.0\Common\Licensing",
        "HKCU:\Software\Microsoft\Office\16.0\Registration"
    )

    foreach ($path in $registryPaths) {
        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Execute cleanup
Cleanup-Office

# Function to check Windows version and execute appropriate tool
function Check-WindowsVersionAndRunTool {
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -ne 10) {
        exit 1
    }

    $build = $osVersion.Build
    $root = Split-Path -Parent $MyInvocation.MyCommand.Definition

    if ($build -ge 18900) {
        $tool = "$root\v2004\CleanupWPJ_X86.exe"
    } elseif ($build -ge 18000) {
        $tool = "$root\v1903\CleanupWPJ_X86.exe"
    } elseif ($build -ge 17700) {
        $tool = "$root\v1809\CleanupWPJ_X86.exe"
    } elseif ($build -ge 17000) {
        $tool = "$root\v1803\CleanupWPJ_X86.exe"
    } elseif ($build -ge 16000) {
        $tool = "$root\v1709\CleanupWPJ_X86.exe"
    } else {
        exit 1
    }

    & $tool
    $output = Get-Content "output.txt"

    $foundError = $false

    function Review-Line {
        param (
            [string]$line
        )
        
        $error = $line.Substring($line.Length - 11, 10)
        if ($error -ne "0x80000018") {
            $script:foundError = $true
        }
    }

    $output | ForEach-Object { Review-Line $_ }

    if ($foundError) {
        exit 2
    }

    exit 0
}

Check-WindowsVersionAndRunTool

# Function to clear all Outlook profiles for a specific user
function Clear-AllOutlookProfiles {
    param (
        [string]$userSID
    )

    $outlookProfilesKeyPath = "Registry::HKEY_USERS\$userSID\Software\Microsoft\Office\16.0\Outlook\Profiles"
    $outlookDefaultProfileKeyPath = "Registry::HKEY_USERS\$userSID\Software\Microsoft\Office\16.0\Outlook"

    # Remove all profiles
    if (Test-Path -Path $outlookProfilesKeyPath) {
        Remove-Item -Path $outlookProfilesKeyPath -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Remove default profile settings
    if (Test-Path -Path $outlookDefaultProfileKeyPath) {
        Remove-ItemProperty -Path $outlookDefaultProfileKeyPath -Name "DefaultProfile" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $outlookDefaultProfileKeyPath -Name "DefaultProfileStore" -ErrorAction SilentlyContinue
    }
}

# Get all user SIDs from HKEY_USERS
$userSIDs = Get-ChildItem -Path "Registry::HKEY_USERS" | Where-Object { $_.Name -match 'S-1-5-21-[0-9-]+$' }

foreach ($userSID in $userSIDs) {
    # Clear all Outlook profiles for each user
    Clear-AllOutlookProfiles -userSID $userSID.PSChildName
}
