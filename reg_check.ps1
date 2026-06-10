<#
.SYNOPSIS
    Fast Registry Check for common Windows Security & Privilege Escalation vectors.
.DESCRIPTION
    This script checks relevant registry keys and compares them to secure defaults.
    It now includes explanations of the values and the associated risks.
#>

$Checks = @(
    # --- LSA & Credentials ---
    [PSCustomObject]@{
        Category = "Credentials"
        Name = "LSA Protection (RunAsPPL)"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Key = "RunAsPPL"
        SecureValues = @(1, 2)
        InsecureIfMissing = $true
        ValuesInfo = "0=Disabled, 1=Enabled, 2=Audit Mode"
        RiskExplanation = "Prevents non-system processes (like Mimikatz) from reading LSASS memory to extract credentials."
    },
    [PSCustomObject]@{
        Category = "Credentials"
        Name = "Credential Guard (LsaCfgFlags)"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Key = "LsaCfgFlags"
        SecureValues = @(1, 2)
        InsecureIfMissing = $true
        ValuesInfo = "0=Disabled, 1=Enabled (UEFI Lock), 2=Enabled (No Lock)"
        RiskExplanation = "Isolates secrets using Virtualization-Based Security (VBS) so even SYSTEM cannot dump them."
    },
    [PSCustomObject]@{
        Category = "Credentials"
        Name = "WDigest Authentication (UseLogonCredential)"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        Key = "UseLogonCredential"
        SecureValues = @(0)
        InsecureIfMissing = $false # Secure default is missing/0
        ValuesInfo = "0=Disabled (Secure), 1=Enabled (Vulnerable)"
        RiskExplanation = "If enabled, Windows stores passwords in cleartext in LSASS memory."
    },

    # --- UAC (User Account Control) ---
    [PSCustomObject]@{
        Category = "UAC"
        Name = "UAC Enabled (EnableLUA)"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Key = "EnableLUA"
        SecureValues = @(1)
        InsecureIfMissing = $true
        ValuesInfo = "0=Disabled, 1=Enabled"
        RiskExplanation = "If 0, all admin apps run with full privileges automatically, breaking the UAC security boundary."
    },
    [PSCustomObject]@{
        Category = "UAC"
        Name = "UAC Prompt Behavior Admin (ConsentPromptBehaviorAdmin)"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Key = "ConsentPromptBehaviorAdmin"
        SecureValues = @(1, 2)
        InsecureIfMissing = $true
        ValuesInfo = "0=Silent Elevate, 1=Prompt Creds, 2=Prompt Consent, 5=Prompt non-Windows binaries"
        RiskExplanation = "Value 0 allows silent privilege escalation. 5 is default but allows UAC bypasses via Windows binaries. 1 or 2 enforce a secure prompt."
    },
    [PSCustomObject]@{
        Category = "UAC"
        Name = "LocalAccountTokenFilterPolicy (Pass-The-Hash for Local Admins)"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Key = "LocalAccountTokenFilterPolicy"
        SecureValues = @(0)
        InsecureIfMissing = $false # If missing, PtH is blocked
        ValuesInfo = "0=Filter Active (Secure), 1=Filter Disabled (Vulnerable)"
        RiskExplanation = "If 1, enables Pass-the-Hash (PtH) for local admin accounts over the network (e.g., via SMB/WinRM)."
    },

    # --- RDP & Network ---
    [PSCustomObject]@{
        Category = "Network"
        Name = "RDP Network Level Authentication (NLA)"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
        Key = "UserAuthentication"
        SecureValues = @(1)
        InsecureIfMissing = $true
        ValuesInfo = "0=Disabled, 1=Enabled"
        RiskExplanation = "Requires auth BEFORE session creation, mitigating DoS and RCE exploits (like BlueKeep)."
    },
    [PSCustomObject]@{
        Category = "Network"
        Name = "LLMNR Disabled (EnableMulticast)"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        Key = "EnableMulticast"
        SecureValues = @(0)
        InsecureIfMissing = $true
        ValuesInfo = "0=Disabled (Secure), 1=Enabled (Vulnerable)"
        RiskExplanation = "If enabled, attackers can poison LLMNR network requests (e.g., using Responder) to steal NTLM hashes."
    }
)

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "      Windows Security Registry Quick-Check      " -ForegroundColor Cyan
Write-Host "=================================================`n" -ForegroundColor Cyan

foreach ($Check in $Checks) {
    $currentValue = $null
    $statusColor = "Yellow"
    $statusText = "UNKNOWN"

    # Check if path and key exist
    if (Test-Path $Check.Path) {
        $keyProps = Get-ItemProperty -Path $Check.Path -ErrorAction SilentlyContinue

        if ($null -ne $keyProps."$($Check.Key)") {
            $currentValue = $keyProps."$($Check.Key)"
        }
    }

    # Evaluation Logic
    if ($null -eq $currentValue) {
        $displayValue = "Not Set (Missing)"
        if ($Check.InsecureIfMissing) {
            $statusColor = "Red"
            $statusText = "VULNERABLE / DEFAULT"
        } else {
            $statusColor = "Green"
            $statusText = "SECURE DEFAULT"
        }
    } else {
        $displayValue = $currentValue
        if ($Check.SecureValues -contains $currentValue) {
            $statusColor = "Green"
            $statusText = "SECURE"
        } else {
            $statusColor = "Red"
            $statusText = "VULNERABLE / WEAK"
        }
    }

    $secureValsStr = $Check.SecureValues -join " or "

    # Formatted Output
    Write-Host "[$($Check.Category)] $($Check.Name)" -ForegroundColor White
    Write-Host "  -> Path:     $($Check.Path)\$($Check.Key)" -ForegroundColor DarkGray
    Write-Host "  -> Value:    $displayValue" -NoNewline
    Write-Host " [$statusText]" -ForegroundColor $statusColor
    Write-Host "  -> Expected: $secureValsStr" -ForegroundColor DarkGray
    Write-Host "  -> Values:   $($Check.ValuesInfo)" -ForegroundColor DarkGray
    Write-Host "  -> Risk:     $($Check.RiskExplanation)`n" -ForegroundColor Gray
}

Write-Host "Check completed." -ForegroundColor Cyan
