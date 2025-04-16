# ========================
# Config Variables
# ========================
$InterfaceInternet = "Ethernet"
$InterfaceVanPhong = "Ethernet 2"
$InterfaceBaoVe    = "Ethernet 3"

$IPInternet = "10.0.2.10"
$IPVanPhong = "192.168.10.10"
$IPBaoVe    = "192.168.20.10"
$Netmask    = 24
$Gateway    = "10.0.2.2"
$Domain     = "toanha.local"
$DNSServer  = $IPInternet
$LogFile    = "C:\setup_log.txt"

# ========================
# Start Logging
# ========================
Start-Transcript -Path $LogFile -Force
Write-Host "=== BAT DAU CAI DAT: $(Get-Date) ==="

# ========================
# Kiem tra quyen Admin
# ========================
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Hay chay script voi quyen Administrator."
    exit 1
}

# ========================
# Kiem tra giao dien mang
# ========================
Write-Host "Kiem tra giao dien mang..."
foreach ($iface in @($InterfaceInternet, $InterfaceVanPhong, $InterfaceBaoVe)) {
    if (-not (Get-NetAdapter -Name $iface -ErrorAction SilentlyContinue)) {
        Write-Host "Giao dien $iface khong ton tai."
        exit 1
    }
}

# ========================
# Gan IP tinh
# ========================
Write-Host "Cau hinh IP tinh cho $InterfaceInternet..."
# Xoa IP cu neu co
Get-NetIPAddress -InterfaceAlias $InterfaceInternet -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
New-NetIPAddress -InterfaceAlias $InterfaceInternet -IPAddress $IPInternet -PrefixLength $Netmask -DefaultGateway $Gateway -ErrorAction Stop
Set-DnsClientServerAddress -InterfaceAlias $InterfaceInternet -ServerAddresses ($DNSServer, "8.8.8.8")

Write-Host "Cau hinh IP tinh cho $InterfaceVanPhong..."
# Xoa IP cu neu co
Get-NetIPAddress -InterfaceAlias $InterfaceVanPhong -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
New-NetIPAddress -InterfaceAlias $InterfaceVanPhong -IPAddress $IPVanPhong -PrefixLength $Netmask -ErrorAction Stop

Write-Host "Cau hinh IP tinh cho $InterfaceBaoVe..."
# Xoa IP cu neu co
Get-NetIPAddress -InterfaceAlias $InterfaceBaoVe -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
New-NetIPAddress -InterfaceAlias $InterfaceBaoVe -IPAddress $IPBaoVe -PrefixLength $Netmask -ErrorAction Stop

# ========================
# Cai DHCP va DNS
# ========================
Write-Host "Cai dat vai tro DHCP va DNS..."
Install-WindowsFeature -Name DHCP -IncludeManagementTools
Install-WindowsFeature -Name DNS -IncludeManagementTools
Import-Module DHCPServer

# ========================
# Tao Scope DHCP
# ========================
Write-Host "Tao scope DHCP tren dai 10.0.2.0/24..."
Add-DhcpServerv4Scope -Name "InternetLAN" -StartRange 10.0.2.100 -EndRange 10.0.2.200 -SubnetMask 255.255.255.0
Set-DhcpServerv4OptionValue -ScopeId 10.0.2.0 -Router $Gateway -DnsServer $DNSServer -DnsDomain $Domain

Write-Host "Tao scope DHCP tren dai 192.168.10.0/24..."
Add-DhcpServerv4Scope -Name "VanPhongLAN" -StartRange 192.168.10.100 -EndRange 192.168.10.200 -SubnetMask 255.255.255.0
Set-DhcpServerv4OptionValue -ScopeId 192.168.10.0 -Router $IPVanPhong -DnsServer $DNSServer -DnsDomain $Domain

Write-Host "Tao scope DHCP tren dai 192.168.20.0/24..."
Add-DhcpServerv4Scope -Name "BaoVeLAN" -StartRange 192.168.20.100 -EndRange 192.168.20.200 -SubnetMask 255.255.255.0
Set-DhcpServerv4OptionValue -ScopeId 192.168.20.0 -Router $IPBaoVe -DnsServer $DNSServer -DnsDomain $Domain

Restart-Service DHCPServer

# ========================
# DNS Zone
# ========================
Write-Host "Cau hinh DNS zone $Domain..."
Add-DnsServerPrimaryZone -Name $Domain -ZoneFile "$Domain.dns" -DynamicUpdate Secure
Add-DnsServerResourceRecordA -Name "ns1" -ZoneName $Domain -IPv4Address $IPInternet
Restart-Service DNS

# ========================
# Bat IP Forwarding
# ========================
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IPEnableRouter" -Value 1

# ========================
# Cai dat NFS Server
# ========================
Write-Host "Cai dat vai tro NFS Server..."
Install-WindowsFeature -Name FS-NFS-Service -IncludeManagementTools

# Tao nhom
$Groups = @("vanphong", "baove", "nhansu", "ketoan")
foreach ($group in $Groups) {
    if (-not (Get-LocalGroup -Name $group -ErrorAction SilentlyContinue)) {
        New-LocalGroup -Name $group -Description "Nhom truy cap thu muc $group"
    }
}

# Tao thu muc chia se
$ShareBase = "C:\Share"
$SharePaths = @{
    vanphong = "$ShareBase\vanphong"
    baove    = "$ShareBase\baove"
    nhansu   = "$ShareBase\nhansu"
    ketoan   = "$ShareBase\ketoan"
}

foreach ($key in $SharePaths.Keys) {
    $path = $SharePaths[$key]

    # Tao thu muc
    New-Item -Path $path -ItemType Directory -Force | Out-Null

    # Gan quyen NTFS cho nhom
    $acl = Get-Acl $path
    $acl.SetAccessRuleProtection($true, $false) # Disable inheritance
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $key, "Modify", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $acl.AddAccessRule($rule)
    Set-Acl -Path $path -AclObject $acl

    # Chia se qua NFS
    if (-not (Get-NfsShare -Name $key -ErrorAction SilentlyContinue)) {
        New-NfsShare -Name $key -Path $path -Permission ReadWrite -AllowAnonymousAccess $false -Authentication "sys" -EnableUnmappedUserAccess $false
        Grant-NfsSharePermission -Name $key -ClientName "ALL MACHINES" -ClientType "host" -Permission "ReadWrite" -AllowRootAccess $false
    }
}

# Tao nguoi dung va gan vao nhom
Write-Host "Tao nguoi dung va gan nhom..."
$Users = @{
    LinhKeToan  = "vanphong"
    TaiNhanSu   = "vanphong"
    ThienBaoVe  = "baove"
    Nhanbaove   = "baove"
    Nhannhansu  = "nhansu"
    BaoKeToan   = "ketoan"
}

foreach ($user in $Users.Keys) {
    if (-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue)) {
        $pass = ConvertTo-SecureString "123456" -AsPlainText -Force
        New-LocalUser -Name $user -Password $pass -FullName $user -Description "Nguoi dung $user"
        Add-LocalGroupMember -Group $Users[$user] -Member $user
    }
}

# ========================
# Cau hinh Firewall
# ========================
Write-Host "Cau hinh firewall..."
New-NetFirewallRule -DisplayName "Allow DHCP Server" -Direction Inbound -Protocol UDP -LocalPort 67 -Action Allow
New-NetFirewallRule -DisplayName "Allow DNS" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow
New-NetFirewallRule -DisplayName "Allow NFS" -Direction Inbound -Protocol TCP -LocalPort 2049 -Action Allow
New-NetFirewallRule -DisplayName "Allow NFS Mount" -Direction Inbound -Protocol TCP -LocalPort 111 -Action Allow

# ========================
# DONE
# ========================
Write-Host "==== CAI DAT HOAN TAT ===="
Write-Host "IP Internet    : $IPInternet"
Write-Host "IP VanPhong    : $IPVanPhong"
Write-Host "IP BaoVe       : $IPBaoVe"
Write-Host "DHCP Pham vi   : 10.0.2.100 - 10.0.2.200, 192.168.10.100 - 192.168.10.200, 192.168.20.100 - 192.168.20.200"
Write-Host "Domain noi bo  : $Domain"
Write-Host "Nguoi dung     : $($Users.Keys -join ', ') (mat khau: 123456)"
Write-Host "Thong tin log  : $LogFile"
Stop-Transcript