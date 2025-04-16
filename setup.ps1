#Requires -RunAsAdministrator

# ========================
# Bien cau hinh
# ========================
$INTERFACE_INTERNET = "Ethernet"
$INTERFACE_VANPHONG = "Ethernet 2"
$INTERFACE_BAOVE = "Ethernet 3"
$IP_INTERNET = "192.168.100.10"
$IP_VANPHONG = "192.168.10.10"
$IP_BAOVE = "192.168.20.10"
$NETMASK = "255.255.255.0"
$DOMAIN = "toanha.local"
$DNS_SERVER = $IP_INTERNET
$LOG_FILE = "C:\setup_log.txt"

# ========================
# Kiem tra quyen admin
# ========================
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Hay chay script voi quyen Administrator."
    exit 1
}

# ========================
# Tao log
# ========================
"=== BAT DAU CAI DAT: $(Get-Date) ===" | Out-File -FilePath $LOG_FILE

# ========================
# Kiem tra giao dien mang
# ========================
"==== Kiem tra giao dien mang ====" | Out-File -FilePath $LOG_FILE -Append
foreach ($iface in @($INTERFACE_INTERNET, $INTERFACE_VANPHONG, $INTERFACE_BAOVE)) {
    $adapter = Get-NetAdapter -Name $iface -ErrorAction SilentlyContinue
    if (-not $adapter) {
        "Giao dien $iface khong ton tai." | Out-File -FilePath $LOG_FILE -Append
        exit 1
    }
    if ($adapter.Status -ne "Up") {
        "Giao dien $iface khong hoat dong." | Out-File -FilePath $LOG_FILE -Append
        exit 1
    }
}

# ========================
# Cau hinh IP tinh
# ========================
"==== Cau hinh IP tinh ====" | Out-File -FilePath $LOG_FILE -Append

New-NetIPAddress -InterfaceAlias $INTERFACE_INTERNET -IPAddress $IP_INTERNET -PrefixLength 24 -DefaultGateway $IP_INTERNET -ErrorAction Stop
Set-DnsClientServerAddress -InterfaceAlias $INTERFACE_INTERNET -ServerAddresses ("8.8.8.8", "1.1.1.1")

New-NetIPAddress -InterfaceAlias $INTERFACE_VANPHONG -IPAddress $IP_VANPHONG -PrefixLength 24 -ErrorAction Stop
Set-DnsClientServerAddress -InterfaceAlias $INTERFACE_VANPHONG -ServerAddresses $DNS_SERVER

New-NetIPAddress -InterfaceAlias $INTERFACE_BAOVE -IPAddress $IP_BAOVE -PrefixLength 24 -ErrorAction Stop
Set-DnsClientServerAddress -InterfaceAlias $INTERFACE_BAOVE -ServerAddresses $DNS_SERVER

"IP tĩnh đã được áp dụng." | Out-File -FilePath $LOG_FILE -Append

# ========================
# Cap nhat he thong (Windows Update)
# ========================
"==== Cap nhat he thong ====" | Out-File -FilePath $LOG_FILE -Append
Install-Module -Name PSWindowsUpdate -Force -Confirm:$false
Import-Module -Name PSWindowsUpdate
Get-WindowsUpdate -Install -AcceptAll -AutoReboot:$false | Out-File -FilePath $LOG_FILE -Append

# ========================
# Cai dat DHCP Server
# ========================
"==== Cai dat DHCP Server ====" | Out-File -FilePath $LOG_FILE -Append
Install-WindowsFeature -Name DHCP -IncludeManagementTools -ErrorAction Stop

Add-DhcpServerv4Scope -Name "VanPhong" -StartRange "192.168.10.100" -EndRange "192.168.10.200" -SubnetMask $NETMASK -State Active
Set-DhcpServerv4OptionValue -ScopeId "192.168.10.0" -Router $IP_VANPHONG -DnsServer $DNS_SERVER -DnsDomain $DOMAIN

Add-DhcpServerv4Scope -Name "BaoVe" -StartRange "192.168.20.100" -EndRange "192.168.20.200" -SubnetMask $NETMASK -State Active
Set-DhcpServerv4OptionValue -ScopeId "192.168.20.0" -Router $IP_BAOVE -DnsServer $DNS_SERVER -DnsDomain $DOMAIN

Restart-Service -Name DHCPServer
"DHCP Server da duoc cai dat va chay." | Out-File -FilePath $LOG_FILE -Append

# ========================
# Cai dat DNS Server
# ========================
"==== Cai dat DNS Server ====" | Out-File -FilePath $LOG_FILE -Append
Install-WindowsFeature -Name DNS -IncludeManagementTools -ErrorAction Stop

Add-DnsServerPrimaryZone -Name $DOMAIN -ZoneFile "$DOMAIN.dns" -DynamicUpdate Secure
Add-DnsServerResourceRecordA -Name "ns1" -ZoneName $DOMAIN -IPv4Address $IP_INTERNET
Add-DnsServerResourceRecordA -Name "server" -ZoneName $DOMAIN -IPv4Address $IP_INTERNET

"DNS Server da duoc cau hinh." | Out-File -FilePath $LOG_FILE -Append

# ========================
# Tao nguoi dung va chia se thu muc
# ========================
"==== Tao nguoi dung va chia se thu muc ====" | Out-File -FilePath $LOG_FILE -Append

$groups = @("vanphong", "baove", "nhansu", "ketoan")
foreach ($g in $groups) { New-LocalGroup -Name $g -ErrorAction SilentlyContinue }

$users = @{
    "LinhKeToan" = "vanphong"
    "TaiNhanSu" = "vanphong"
    "ThienBaoVe" = "baove"
    "Nhanbaove" = "baove"
    "Nhannhansu" = "nhansu"
    "BaoKeToan" = "ketoan"
}

foreach ($user in $users.Keys) {
    net user $user "123456" /add /y
    Add-LocalGroupMember -Group $users[$user] -Member $user
}

$shares = @("vanphong", "baove", "nhansu", "ketoan")
foreach ($s in $shares) {
    $path = "C:\Share\$s"
    New-Item -Path $path -ItemType Directory -Force | Out-Null
    icacls $path /grant "$s:(OI)(CI)F" | Out-Null
    New-SmbShare -Name $s -Path $path -FullAccess $s
}

"Thu muc da duoc chia se voi quyen theo nhom." | Out-File -FilePath $LOG_FILE -Append

# ========================
# Cau hinh Firewall
# ========================
"==== Cau hinh Firewall ====" | Out-File -FilePath $LOG_FILE -Append
Enable-NetFirewallRule -DisplayGroup "DHCP Server"
Enable-NetFirewallRule -DisplayGroup "DNS Server"
Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing"
"Firewall da duoc cau hinh." | Out-File -FilePath $LOG_FILE -Append

# ========================
# Hoan tat
# ========================
"==== CAI DAT HOAN TAT ====" | Out-File -FilePath $LOG_FILE -Append
"IP Internet : $IP_INTERNET" | Out-File -FilePath $LOG_FILE -Append
"IP VanPhong : $IP_VANPHONG" | Out-File -FilePath $LOG_FILE -Append
"IP BaoVe    : $IP_BAOVE" | Out-File -FilePath $LOG_FILE -Append
"DOMAIN noi bo: $DOMAIN" | Out-File -FilePath $LOG_FILE -Append
"Nguoi dung: $($users.Keys -join ', ') (mat khau: 123456)" | Out-File -FilePath $LOG_FILE -Append
"Log tai: $LOG_FILE" | Out-File -FilePath $LOG_FILE -Append
"=== HOAN TAT: $(Get-Date) ===" | Out-File -FilePath $LOG_FILE -Append
