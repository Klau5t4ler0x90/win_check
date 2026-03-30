$portList = @{
    21    = "FTP"
    22    = "SSH"
    23    = "Telnet"
    25    = "SMTP"
    53    = "DNS"
    80    = "HTTP"
    135   = "RPC"
    139   = "NetBIOS"
    443   = "HTTPS"
    445   = "SMB"
    1433  = "MSSQL"
    3306  = "MySQL"
    3389  = "RDP"
    5900  = "VNC"
    5985  = "WinRM (HTTP)"
    8080  = "HTTP-Proxy/Alt"
}

$subnet = "192.168.1"
$range = 1..254
$timeout = 100

Write-Host "`n[*] Starting port scan on subnet: $subnet.0/24" -ForegroundColor Cyan
Write-Host "[*] Mode: TCP-Connect (User-Level, No Admin required)`n" -ForegroundColor Gray

foreach ($ip_suffix in $range) {
    $ip = "$subnet.$ip_suffix"
    $openPorts = @()

    foreach ($port in $portList.Keys | Sort-Object) {
        $tcpClient = New-Object Net.Sockets.TcpClient
        $connect = $tcpClient.ConnectAsync($ip, $port)

        if ($connect.Wait($timeout)) {
            if ($tcpClient.Connected) {
                $service = $portList[$port]
                $openPorts += [PSCustomObject]@{
                    Port    = $port
                    Service = $service
                }
            }
        }
        $tcpClient.Close()
    }

    if ($openPorts.Count -gt 0) {
        Write-Host "[+] Host discovered: $ip" -ForegroundColor Green
        $openPorts | Format-Table -Property Port, Service -AutoSize
        Write-Host "------------------------------------" -ForegroundColor Gray
    }
}
