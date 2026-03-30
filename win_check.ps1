Write-Host "--- [1] WSUS Check (MitM Potential) ---" -ForegroundColor Cyan
$wsus = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue
if ($wsus) {
    echo "WSUS Server: $($wsus.WUServer)"
    if ($wsus.WUServer -notlike "https*") {
        Write-Host "[!] WARNING: WSUS does not use HTTPS! Vulnerable to MitM/Spoofing." -ForegroundColor Red
    }
} else { echo "No specific WSUS configured." }

Write-Host "`n--- [2] Unquoted Service Paths ---" -ForegroundColor Cyan
Get-WmiObject -Class Win32_Service | Where-Object {$_.PathName -notlike '"*' -and $_.PathName -like '* *' -and $_.PathName -notlike 'C:\Windows\*'} |
Select-Object Name, PathName, StartMode | Format-Table -AutoSize

Write-Host "`n--- [3] AlwaysInstallElevated Check ---" -ForegroundColor Cyan
$aieHKCU = Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
$aieHKLM = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
if ($aieHKCU.AlwaysInstallElevated -eq 1 -and $aieHKLM.AlwaysInstallElevated -eq 1) {
    Write-Host "[!!!] CRITICAL: AlwaysInstallElevated is enabled! MSI files run as SYSTEM." -ForegroundColor Red
} else { echo "Disabled (Safe)." }

Write-Host "`n--- [4] Searching for Passwords in Files (Unattend/Configs) ---" -ForegroundColor Cyan
$paths = @("C:\unattend.xml", "C:\Windows\Panther\Unattend.xml", "C:\web.config")
foreach ($path in $paths) {
    if (Test-Path $path) { Write-Host "[!] File found: $path - Manual inspection required!" -ForegroundColor Yellow }
}

Write-Host "`n--- [5] Citrix-specific Paths & Permissions ---" -ForegroundColor Cyan
$citrixPath = "C:\Program Files\Citrix"
if (Test-Path $citrixPath) {
    Write-Host "Citrix installation found. Checking write permissions..."
    $acl = Get-Acl $citrixPath
    $acl.Access | Where-Object { $_.IdentityReference -eq "Everyone" -or $_.IdentityReference -eq "Users" } | Select-Object IdentityReference, FileSystemRights
}

Write-Host "`n--- [6] Searching for Stored Session Data (Admins) ---" -ForegroundColor Cyan

$winscpPath = "HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions"
if (Test-Path $winscpPath) {
    Write-Host "[!] WinSCP sessions found!" -ForegroundColor Yellow
    Get-ChildItem $winscpPath | ForEach-Object {
        $session = $_.PSChildName
        $pass = Get-ItemProperty -Path "$winscpPath\$session" -Name "Password" -ErrorAction SilentlyContinue
        if ($pass) { echo "Session found: $session (Stored password exists)" }
    }
}

$puttyPath = "HKCU:\Software\Simontatham\PuTTY\Sessions"
if (Test-Path $puttyPath) {
    Write-Host "[!] PuTTY sessions found!" -ForegroundColor Yellow
    Get-ChildItem $puttyPath | Select-Object PSChildName | ForEach-Object { echo "Target Host: $($_.PSChildName)" }
}

Write-Host "[*] Checking RDP connection history..."
$rdpHistory = "HKCU:\Software\Microsoft\Terminal Server Client\Servers"
if (Test-Path $rdpHistory) {
    Get-ChildItem $rdpHistory | ForEach-Object {
        echo "RDP Target: $($_.PSChildName)"
    }
}

$savedCreds = cmdkey /list | Select-String "target=TERMSRV"
if ($savedCreds) {
    Write-Host "[!!!] Saved RDP credentials found in Credential Manager!" -ForegroundColor Red
    $savedCreds | ForEach-Object { echo $_.ToString().Trim() }
}

Write-Host "`n--- [7] Scheduled Tasks (Privilege Escalation) ---" -ForegroundColor Cyan

$tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\Windows*" -and $_.State -ne "Disabled" }

foreach ($task in $tasks) {
    $taskName = $task.TaskName
    $taskInfo = Get-ScheduledTask -TaskName $taskName
    $principal = $taskInfo.Principal.UserId

    if ($principal -match "SYSTEM" -or $principal -match "Administrator") {
        $action = $taskInfo.Actions.Execute
        $argument = $taskInfo.Actions.Arguments

        Write-Host "[!] Suspicious task found: $taskName" -ForegroundColor Yellow
        Write-Host "    Runs as: $principal"
        Write-Host "    Command: $action $argument"

        if ($action -and (Test-Path $action)) {
            $acl = Get-Acl $action
            $permissions = $acl.Access | Where-Object { $_.IdentityReference -match "Everyone|Users|Authenticated Users" -and $_.FileSystemRights -match "Write|FullControl|Modify" }

            if ($permissions) {
                Write-Host "[!!!] EXPLOIT POTENTIAL: File is WRITABLE by standard users!" -ForegroundColor Red
                Write-Host "    Path: $action"
            }
        }
    }
}
