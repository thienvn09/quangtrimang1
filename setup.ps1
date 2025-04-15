#Requires -RunAsAdministrator

# ========================
# Biến cấu hình
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
# Kiểm tra quyền Administrator
# ========================
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Hay chay script voi quyen Administrator."
    exit 1
}

# ========================
# Tạo file log
# ========================
"=== BAT DAU CAI DAT: $(Get-Date) ===" | Out-File -FilePath $LOG_FILE -Append

# ========================
# Kiểm tra giao diện mạng
# ========================
"==== Kiem tra giao dien mang ====" | Out-File -FilePath $LOG_FILE -Append
foreach ($iface in @($INTERFACE_INTERNET, $INTERFACE_VANPHONG, $INTERFACE_BAOVE)) {
    $adapter = Get-NetAdapter -Name $iface -ErrorAction SilentlyContinue
    if (-not $adapter) {
        "Giao dien $iface khong ton tai." | Out-File -FilePath $LOG_FILE -Append
        exit 1
    }
    if ($adapter.Status -ne "Up") {
        "Giao dien $iface khong hoat dong (Media disconnected). Vui long kiem tra ket noi mang." | Out-File -FilePath $LOG_FILE -Append
        exit 1
    }
}

# ========================
# Cấu hình IP tĩnh
# ========================
"==== Cau hinh IP tinh ====" | Out-File -FilePath $LOG_FILE -Append

New-NetIPAddress -InterfaceAlias $INTERFACE_INTERNET -IPAddress $IP_INTERNET -PrefixLength 24 -DefaultGateway $IP_INTERNET -ErrorAction Stop | Out-File -FilePath $LOG_FILE -Append
Set-DnsClientServerAddress -InterfaceAlias $INTERFACE_INTERNET -ServerAddresses ("8.8.8.8", "1.1.1.1") -ErrorAction Stop | Out-File -FilePath $LOG_FILE -Append

New-NetIPAddress -InterfaceAlias $INTERFACE_VANPHONG -IPAddress $IP_VANPHONG -PrefixLength 24 -ErrorAction Stop | Out-File -FilePath $LOG_FILE -Append
Set-DnsClientServerAddress -InterfaceAlias $INTERFACE_VANPHONG -ServerAddresses $DNS_SERVER -ErrorAction Stop | Out-File -FilePath $LOG_FILE -Append

New-NetIPAddress -InterfaceAlias $INTERFACE_BAOVE -IPAddress $IP_BAOVE -PrefixLength 24 -ErrorAction Stop | Out-File -FilePath $LOG_FILE -Append
Set-DnsClientServerAddress -InterfaceAlias $INTERFACE_BAOVE -ServerAddresses $DNS_SERVER -ErrorAction Stop | Out-File -FilePath $LOG_FILE -Append

"IP tĩnh đã được áp dụng." | Out-File -FilePath $LOG_FILE -Append

# ========================
# Cài đặt và cấu hình DHCP Server
# ========================
"==== Cai dat DHCP Server ====" | Out-File -FilePath $LOG_FILE -Append

Install-WindowsFeature -Name DHCP -IncludeManagementTools -ErrorAction Stop | Out-File -FilePath $LOG_FILE -Append

Add-DhcpServerv4Scope -Name "VanPhong" -StartRange "192.168.10.100" -EndRange "192.168.10.200" -SubnetMask $NETMASK -State Active -ErrorAction Stop
Set-DhcpServerv4OptionValue -ScopeId "192.168.10.0" -Router $IP_VANPHONG -DnsServer $DNS_SERVER -DnsDomain $DOMAIN -ErrorAction Stop

Add-DhcpServerv4Scope -Name "BaoVe" -StartRange "192.168.20.100" -EndRange "192.168.20.200" -SubnetMask $NETMASK -State Active -ErrorAction Stop
Set-DhcpServerv4OptionValue -ScopeId "192.168.20.0" -Router $IP_BAOVE -DnsServer $DNS_SERVER -DnsDomain $DOMAIN -ErrorAction Stop

Restart-Service -Name DHCPServer -ErrorAction Stop
"DHCP Server da duoc cai dat va chay." | Out-File -FilePath $LOG_FILE -Append

# ========================
# Cài đặt DNS Server
# ========================
"==== Cai dat DNS Server ====" | Out-File -FilePath $LOG_FILE -Append

Install-WindowsFeature -Name DNS -IncludeManagementTools -ErrorAction Stop | Out-File -FilePath $LOG_FILE -Append

Add-DnsServerPrimaryZone -Name $DOMAIN -ZoneFile "$DOMAIN.dns" -ErrorAction Stop
Add-DnsServerResourceRecordA -ZoneName $DOMAIN -Name "ns1" -IPv4Address $IP_INTERNET -ErrorAction Stop
Add-DnsServerResourceRecordA -ZoneName $DOMAIN -Name "@" -IPv4Address $IP_INTERNET -ErrorAction Stop
Add-DnsServerForwarder -IPAddress "8.8.8.8", "1.1.1.1" -ErrorAction Stop

"DNS Server da duoc cau hinh dung va chay." | Out-File -FilePath $LOG_FILE -Append

# ========================
# Cài đặt và cấu hình chia sẻ file (SMB thay cho Samba)
# ========================
"==== Cai dat File Sharing ====" | Out-File -FilePath $LOG_FILE -Append

Install-WindowsFeature -Name FS-FileServer -ErrorAction Stop | Out-File -FilePath $LOG_FILE -Append

$SHARE_PATHS = @("C:\srv\share\vanphong", "C:\srv\share\baove", "C:\srv\share\nhansu", "C:\srv\share\ketoan")
foreach ($path in $SHARE_PATHS) {
    New-Item -Path $path -ItemType Directory -Force | Out-Null
}

$Groups = @("vanphong", "baove", "nhansu", "ketoan")
foreach ($group in $Groups) {
    New-LocalGroup -Name $group -ErrorAction SilentlyContinue
}

$SHARE_ACLS = @{
    "C:\srv\share\vanphong" = "vanphong"
    "C:\srv\share\baove" = "baove"
    "C:\srv\share\nhansu" = "nhansu"
    "C:\srv\share\ketoan" = "ketoan"
}
foreach ($path in $SHARE_ACLS.Keys) {
    $group = $SHARE_ACLS[$path]
    $acl = Get-Acl $path
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($group, "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.SetAccessRule($rule)
    Set-Acl $path $acl
}

$USERS = @{
    "LinhKeToan" = "vanphong"
    "TaiNhanSu" = "vanphong"
    "ThienBaoVe" = "baove"
    "Nhanbaove" = "baove"
    "Nhannhansu" = "nhansu"
    "BaoKeToan" = "ketoan"
}

foreach ($user in $USERS.Keys) {
    $group = $USERS[$user]
    $password = ConvertTo-SecureString "Adm!n2025" -AsPlainText -Force
    New-LocalUser -Name $user -Password $password -PasswordNeverExpires -AccountNeverExpires -ErrorAction SilentlyContinue
    Add-LocalGroupMember -Group $group -Member $user -ErrorAction SilentlyContinue
}

foreach ($path in $SHARE_ACLS.Keys) {
    $shareName = Split-Path $path -Leaf
    $group = $SHARE_ACLS[$path]
    New-SmbShare -Name $shareName -Path $path -FullAccess $group -ErrorAction Stop
}

"File Sharing da duoc cau hinh dung cach." | Out-File -FilePath $LOG_FILE -Append

# ========================
# Cấu hình IP Forwarding và Firewall
# ========================
"==== Cau hinh IP Forward va Firewall ====" | Out-File -FilePath $LOG_FILE -Append

Install-WindowsFeature -Name Routing -IncludeManagementTools -ErrorAction Stop
Start-Service RemoteAccess -ErrorAction Stop
$rrasConfig = "netsh routing ip nat install; netsh routing ip nat add interface $($INTERFACE_INTERNET); netsh routing ip nat add interface $($INTERFACE_VANPHONG); netsh routing ip nat add interface $($INTERFACE_BAOVE)"
Invoke-Expression $rrasConfig | Out-File -FilePath $LOG_FILE -Append

New-NetFirewallRule -DisplayName "Allow DHCP" -Direction Inbound -Protocol UDP -LocalPort 67 -Action Allow -ErrorAction Stop
New-NetFirewallRule -DisplayName "Allow DNS" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow -ErrorAction Stop
New-NetFirewallRule -DisplayName "Allow SMB" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow -ErrorAction Stop
New-NetFirewallRule -DisplayName "Allow Interfaces" -Direction Inbound -InterfaceAlias $INTERFACE_INTERNET, $INTERFACE_VANPHONG, $INTERFACE_BAOVE -Action Allow -ErrorAction Stop

# ========================
# Hoàn tất
# ========================
"==== CAI DAT HOAN TAT ====" | Out-File -FilePath $LOG_FILE -Append
"IP Internet : $IP_INTERNET" | Out-File -FilePath $LOG_FILE -Append
"IP VanPhong : $IP_VANPHONG" | Out-File -FilePath $LOG_FILE -Append
"IP BaoVe    : $IP_BAOVE" | Out-File -FilePath $LOG_FILE -Append
"DOMAIN noi bo: $DOMAIN" | Out-File -FilePath $LOG_FILE -Append
"Nguoi dung: $($USERS.Keys -join ', ') (mat khau: Adm!n2025)" | Out-File -FilePath $LOG_FILE -Append
"Thong tin log tai: $LOG_FILE" | Out-File -FilePath $LOG_FILE -Append
"=== HOAN TAT CAI DAT: $(Get-Date) ===" | Out-File -FilePath $LOG_FILE -Append