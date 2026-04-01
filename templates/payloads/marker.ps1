# Marker PowerShell script — deployed by lateral movement modules
# This script DOES NOT encrypt files — it only creates a marker.

param(
    [string]$MarkerPath = "C:\ransomemu_marker.txt",
    [string]$SimId = "default"
)

$timestamp = (Get-Date).ToUniversalTime().ToString("o")
$hostname = $env:COMPUTERNAME
$user = $env:USERNAME

$marker = @"
===== RANSOMEMU SIMULATION MARKER =====
Timestamp: $timestamp
Host: $hostname
User: $user
Simulation ID: $SimId
THIS FILE WAS NOT ENCRYPTED — marker only.
===== RANSOMEMU SIMULATION MARKER =====
"@

Set-Content -Path $MarkerPath -Value $marker -Encoding UTF8

# Collect system info for reporting
$info = @{
    hostname = $hostname
    user = $user
    os = (Get-CimInstance Win32_OperatingSystem).Caption
    ip = (Get-NetIPAddress -AddressFamily IPv4 |
          Where-Object { $_.InterfaceAlias -ne "Loopback Pseudo-Interface 1" } |
          Select-Object -First 1).IPAddress
    timestamp = $timestamp
    sim_id = $SimId
}

$info | ConvertTo-Json
