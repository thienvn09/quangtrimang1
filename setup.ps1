# ========================
# Config Variables
# ========================
$InterfaceInternet = "Ethernet0"
$InterfaceVanPhong = "Ethernet1"
$InterfaceBaoVe    = "Ethernet2"

$IPInternet = "192.168.100.10"
$IPVanPhong = "192.168.10.10"
$IPBaoVe    = "192.168.20.10"
$Netmask    = 24
$Domain     = "toanha.local"
$DNSServer  = $IPInternet
$LogFile    = "C:\setup_log.txt"

# ========================
# Start Logging
# ========================
Start-Transcript -Path $LogFile -Force
Write-Host "=== BAT DAU CAI DAT: $(Get-Date) ==="

# ========================
# IP Configuration
# ========================
function Set-StaticIP {
    param (
        [string]$InterfaceAlias,
        [string]$IPAddress
    )

    Write-Host "Configuring IP for $InterfaceAlias..."
    New-NetIPAddress -InterfaceAlias $InterfaceAlias -IPAddress $IPAddress -PrefixLength $Netmask -DefaultGateway $IPAddress -ErrorAction Stop
    Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses $DNSServer
}

Set-StaticIP -InterfaceAlias $InterfaceInternet -IPAddress $IPInternet
Set-StaticIP -InterfaceAlias $InterfaceVanPhong  -IPAddress $IPVanPhong
Set-StaticIP -InterfaceAlias $InterfaceBaoVe     -IPAddress $IPBaoVe

# ========================
# Install DHCP and DNS
# ========================
Write-Host "Installing DHCP and DNS roles..."
Install-WindowsFeature -Name DHCP -IncludeManagementTools
Install-WindowsFeature -Name DNS -IncludeManagementTools

# ========================
# Configure DHCP Scopes
# ========================
Import-Module DHCPServer

Add-DhcpServerv4Scope -Name "VanPhong" -StartRange 192.168.10.100 -EndRange 192.168.10.200 -SubnetMask 255.255.255.0
Set-DhcpServerv4OptionValue -ScopeId 192.168.10.0 -Router $IPVanPhong -DnsServer $DNSServer -DnsDomain $Domain

Add-DhcpServerv4Scope -Name "BaoVe" -StartRange 192.168.20.100 -EndRange 192.168.20.200 -SubnetMask 255.255.255.0
Set-DhcpServerv4OptionValue -ScopeId 192.168.20.0 -Router $IPBaoVe -DnsServer $DNSServer -DnsDomain $Domain

Restart-Service DHCPServer

# ========================
# DNS Setup (Simple Zone)
# ========================
Add-DnsServerPrimaryZone -Name $Domain -ZoneFile "$Domain.dns" -DynamicUpdate Secure
Add-DnsServerResourceRecordA -Name "ns1" -ZoneName $Domain -IPv4Address $IPInternet

# ========================
# Create Users & Groups
# ========================
$Groups = @("vanphong", "baove", "nhansu", "ketoan")
foreach ($group in $Groups) {
    if (-not (Get-ADGroup -Filter "Name -eq '$group'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $group -GroupScope Global -PassThru
    }
}

$Users = @{
    LinhKeToan = "vanphong"
    TaiNhanSu = "vanphong"
    ThienBaoVe = "baove"
    Nhanbaove = "baove"
    Nhannhansu = "nhansu"
    BaoKeToan = "ketoan"
}

foreach ($user in $Users.Keys) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$user'" -ErrorAction SilentlyContinue)) {
        $pass = ConvertTo-SecureString "123456" -AsPlainText -Force
        New-ADUser -Name $user -AccountPassword $pass -Enabled $true -PasswordNeverExpires $true
        Add-ADGroupMember -Identity $Users[$user] -Members $user
    }
}

# ========================
# Create Share Folders
# ========================
$SharePaths = @{
    VanPhong = "C:\Share\vanphong"
    BaoVe = "C:\Share\baove"
    NhanSu = "C:\Share\nhansu"
    KeToan = "C:\Share\ketoan"
}

foreach ($share in $SharePaths.Keys) {
    $path = $SharePaths[$share]
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    $group = $share.ToLower()
    $acl = Get-Acl $path
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$group", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.SetAccessRule($rule)
    Set-Acl $path $acl
    New-SmbShare -Name $share -Path $path -FullAccess "$group"
}

# ========================
# Enable IP Forwarding
# ========================
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IPEnableRouter" -Value 1

# ========================
# Firewall Configuration
# ========================
Write-Host "Configuring Windows Firewall..."
New-NetFirewallRule -DisplayName "Allow DHCP Server" -Direction Inbound -Protocol UDP -LocalPort 67 -Action Allow
New-NetFirewallRule -DisplayName "Allow DNS" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow
New-NetFirewallRule -DisplayName "Allow SMB" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow

# ========================
# Done
# ========================
Write-Host "==== CAI DAT HOAN TAT ===="
Write-Host "IP Internet : $IPInternet"
Write-Host "IP VanPhong : $IPVanPhong"
Write-Host "IP BaoVe    : $IPBaoVe"
Write-Host "DOMAIN      : $Domain"
Write-Host "Nguoi dung  : $($Users.Keys -join ', ') (mat khau: 123456)"
Write-Host "Thong tin log tai: $LogFile"
Stop-Transcript
