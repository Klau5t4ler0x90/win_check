param(
    [Parameter(Mandatory=$true)]
    [string]$BaseUrl,
    [string]$Wordlist = "paths.txt"
)

[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

if (-not (Test-Path $Wordlist)) {
    Write-Host "[-] Error: $Wordlist not found!" -ForegroundColor Red
    return
}

$paths = Get-Content $Wordlist
Write-Host "[*] Starting enumeration on $BaseUrl" -ForegroundColor Cyan
Write-Host "[*] Loaded paths: $($paths.Count)" -ForegroundColor Cyan
Write-Host "-------------------------------------------"

foreach ($path in $paths) {
    $cleanPath = $path.TrimStart('/')
    $url = "$BaseUrl/$cleanPath"

    try {
        $res = Invoke-WebRequest -Uri $url -Method Head -UseBasicParsing -ErrorAction Stop -TimeoutSec 2

        $status = [int]$res.StatusCode
        if ($status -eq 200) {
            Write-Host "[+] FOUND: $url (Status: $status)" -ForegroundColor Green
        } else {
            Write-Host "[?] INFO: $url (Status: $status)" -ForegroundColor Yellow
        }
    }
    catch {
        $errStatus = [int]$_.Exception.Response.StatusCode

        if ($errStatus -eq 403) {
            Write-Host "[!] FORBIDDEN: $url (Status: 403)" -ForegroundColor DarkYellow
        }
        elseif ($errStatus -eq 401) {
            Write-Host "[!] AUTH REQUIRED: $url (Status: 401)" -ForegroundColor Cyan
        }
        elseif ($errStatus -eq 500) {
            Write-Host "[!] SERVER ERROR: $url (Status: 500)" -ForegroundColor Red
        }
    }
}

Write-Host "-------------------------------------------"
Write-Host "[*] Scan completed." -ForegroundColor Cyan
