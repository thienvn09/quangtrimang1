# Yêu cầu quyền admin
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrator")) {
    Write-Error "Hay chay script voi quyen Administrator!"
    exit 1
}

# ================== CẤU HÌNH ==================
$interfaceVanPhong = "Ethernet0"     # Đổi lại theo card mạng thật
$interfaceBaoVe    = "Ethernet1"
$ipVanPhong        = "192.168.10.10"
$ipBaoVe           = "192.168.20.10"
$prefixLength      = 24
$domain            = "toanha.local"
$dnsServer         = $ipVanPhong
$shareRoot         = "C:\Share"
$users = @{
    "LinhKeToan"  = "VanPhong"
    "TaiNhanSu"   = "VanPhong"
    "ThienBaoVe"  = "BaoVe"
    "Nhanbaove"   = "BaoVe"
    "Nhannhansu"  = "NhanSu"
    "BaoKeToan"   = "KeToan"
}

# ================== CẤU HÌNH IP ==================
Write-Host "==> Cau hinh IP tinh"
New-NetIPAddress -InterfaceAlias $interfaceVanPhong -IPAddress $ipVanPhong -PrefixLength $prefixLength -DefaultGateway "$ipVanPhong"
Set-DnsClientServerAddress -InterfaceAlias $interfaceVanPhong -ServerAddresses $dnsServer

New-NetIPAddress -InterfaceAlias $interfaceBaoVe -IPAddress $ipBaoVe -PrefixLength $prefixLength

# ================== CAI DAT ROLE DHCP & DNS ==================
Write-Host "==> Cai dat DHCP & DNS roles..."
Install-WindowsFeature -Name DHCP,DHCPServer,DNS -IncludeManagementTools

# ================== CAU HINH DHCP ==================
Write-Host "==> Cau hinh DHCP..."
Add-DhcpServerv4Scope -Name "VanPhong" -StartRange 192.168.10.100 -EndRange 192.168.10.200 -SubnetMask 255.255.255.0
Set-DhcpServerv4OptionValue -ScopeId 192.168.10.0 -Router $ipVanPhong -DnsServer $dnsServer -DnsDomain $domain

Add-DhcpServerv4Scope -Name "BaoVe" -StartRange 192.168.20.100 -EndRange 192.168.20.200 -SubnetMask 255.255.255.0
Set-DhcpServerv4OptionValue -ScopeId 192.168.20.0 -Router $ipBaoVe -DnsServer $dnsServer -DnsDomain $domain

Restart-Service dhcpserver

# ================== CAU HINH DNS ==================
Write-Host "==> Cau hinh DNS..."
Add-DnsServerPrimaryZone -Name $domain -ZoneFile "$domain.dns" -ZoneType ForwardLookup
Add-DnsServerResourceRecordA -Name "server" -ZoneName $domain -IPv4Address $ipVanPhong

# ================== TAO THU MUC CHIA SE ==================
Write-Host "==> Tao thu muc va nhom chia se..."
$groups = $users.Values | Sort-Object -Unique
foreach ($group in $groups) {
    net localgroup $group /add
    $path = "$shareRoot\$group"
    New-Item -Path $path -ItemType Directory -Force | Out-Null
    icacls $path /inheritance:r
    icacls $path /grant "Administrators:F"
    icacls $path /grant "$group:(OI)(CI)M"
    net share $group="$path" /GRANT:$group,FULL
}

# ================== TAO NGUOI DUNG ==================
Write-Host "==> Tao nguoi dung va gan vao nhom..."
foreach ($user in $users.Keys) {
    net user $user "123456" /add
    net localgroup $users[$user] $user /add
}

# ================== MO FIREWALL ==================
Write-Host "==> Mo firewall cac dich vu can thiet..."
New-NetFirewallRule -DisplayName "Allow DHCP" -Direction Inbound -Protocol UDP -LocalPort 67 -Action Allow
New-NetFirewallRule -DisplayName "Allow DNS TCP" -Direction Inbound -Protocol TCP -LocalPort 53 -Action Allow
New-NetFirewallRule -DisplayName "Allow DNS UDP" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow
New-NetFirewallRule -DisplayName "Allow File Sharing" -Direction Inbound -Program System -Service "LanmanServer" -Action Allow

# ================== HOAN TAT ==================
Write-Host ""
Write-Host "==== CAU HINH HOAN TAT ===="
Write-Host "IP vanphong: $ipVanPhong"
Write-Host "IP baove: $ipBaoVe"
Write-Host "Ten mien noi bo: $domain"
Write-Host "Thu muc chia se:"
foreach ($group in $groups) {
    Write-Host " - $group: $shareRoot\$group"
}
Write-Host "`nUser mac dinh (mat khau: 123456):"
$users.Keys | ForEach-Object { Write-Host " - $_" }
