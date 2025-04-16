# PowerShell script to configure Windows Server with network, DHCP, DNS, file sharing, and firewall
# Updated to fix errors, handle interfaces correctly, and improve robustness

# Ensure script runs with elevated privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Please run this script as an Administrator."
    exit 1
}

# Configuration Variables
$InterfaceInternet = "Ethernet"
$InterfaceVanPhong = "Ethernet 2"
$InterfaceBaoVe = "Ethernet 3"
$IPInternet = "192.168.100.10"
$IPVanPhong = "192.168.10.10"
$IPBaoVe = "192.168.20.10"
$Netmask = "255.255.255.0"
$PrefixLength = 24
$Domain = "toanha.local"
$DNSServer = $IPInternet
$LogFile = "C:\Setup_Log.txt"

# Initialize Log File
"=== START SETUP: $(Get-Date) ===" | Out-File -FilePath $LogFile -Encoding UTF8

function Write-Log {
    param($Message)
    $Message | Out-File -FilePath $LogFile -Append -Encoding UTF8
    Write-Host $Message
}

# Check Network Interfaces
Write-Log "==== Checking Network Interfaces ===="
foreach ($iface in @($InterfaceInternet, $InterfaceVanPhong, $InterfaceBaoVe)) {
    if (-not (Get-NetAdapter -Name $iface -ErrorAction SilentlyContinue)) {
        Write-Log "Interface $iface does not exist."
        exit 1
    }
}

# Configure Static IPs
Write-Log "==== Configuring Static IPs ===="
try {
    function Set-InterfaceIP {
        param ($InterfaceAlias, $IPAddress, $PrefixLength, $DefaultGateway = $null, $DnsServers = $null)

        $currentIP = Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq $IPAddress }

        if ($currentIP) {
            Write-Log "IP $IPAddress already exists on $InterfaceAlias. Skipping assignment."
        } else {
            Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
            $params = @{
                InterfaceAlias = $InterfaceAlias
                IPAddress = $IPAddress
                PrefixLength = $PrefixLength
                ErrorAction = "Stop"
            }
            if ($DefaultGateway) { $params.DefaultGateway = $DefaultGateway }
            New-NetIPAddress @params | Out-Null
            if ($DnsServers) {
                Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses $DnsServers -ErrorAction Stop
            }
            Write-Log "Assigned IP $IPAddress to $InterfaceAlias."
        }
    }

    Set-InterfaceIP -InterfaceAlias $InterfaceInternet -IPAddress $IPInternet -PrefixLength $PrefixLength -DefaultGateway "192.168.100.1" -DnsServers ("8.8.8.8", "1.1.1.1")
    Set-InterfaceIP -InterfaceAlias $InterfaceVanPhong -IPAddress $IPVanPhong -PrefixLength $PrefixLength
    Set-InterfaceIP -InterfaceAlias $InterfaceBaoVe -IPAddress $IPBaoVe -PrefixLength $PrefixLength

    Write-Log "Network interfaces configured successfully."
}
catch {
    Write-Log "Error configuring network interfaces: $_"
    exit 1
}

# Install and Configure Windows Features
Write-Log "==== Installing Required Features ===="
$features = @("DHCP", "DNS", "FS-FileServer", "FS-SMB1")
foreach ($feature in $features) {
    if (-not (Get-WindowsFeature -Name $feature).Installed) {
        Install-WindowsFeature -Name $feature -IncludeManagementTools -ErrorAction Stop | Out-Null
        Write-Log "Installed feature: $feature"
    }
}

# Configure DHCP Server
Write-Log "==== Configuring DHCP Server ===="
try {
    if ((Get-WmiObject Win32_ComputerSystem).PartOfDomain) {
        Add-DhcpServerInDC -DnsName $env:COMPUTERNAME -IPAddress $IPInternet -ErrorAction Stop
        Write-Log "Authorized DHCP server in Active Directory."
    } else {
        Write-Log "Server not in domain. Skipping DHCP authorization."
    }

    Add-DhcpServerv4Scope -Name "VanPhong" -StartRange "192.168.10.100" -EndRange "192.168.10.200" -SubnetMask $Netmask -State Active -ErrorAction Stop
    Set-DhcpServerv4OptionValue -ScopeId "192.168.10.0" -Router $IPVanPhong -DnsServer $DNSServer -DnsDomain $Domain -ErrorAction Stop

    Add-DhcpServerv4Scope -Name "BaoVe" -StartRange "192.168.20.100" -EndRange "192.168.20.200" -SubnetMask $Netmask -State Active -ErrorAction Stop
    Set-DhcpServerv4OptionValue -ScopeId "192.168.20.0" -Router $IPBaoVe -DnsServer $DNSServer -DnsDomain $Domain -ErrorAction Stop

    Set-DhcpServerv4Binding -InterfaceAlias $InterfaceVanPhong -BindingState $true -ErrorAction Stop
    Set-DhcpServerv4Binding -InterfaceAlias $InterfaceBaoVe -BindingState $true -ErrorAction Stop
    Set-DhcpServerv4Binding -InterfaceAlias $InterfaceInternet -BindingState $false -ErrorAction Stop

    Start-Sleep -Seconds 5
    Restart-Service -Name DHCPServer -ErrorAction Stop
    Write-Log "DHCP Server configured and started."
}
catch {
    Write-Log "Error configuring DHCP Server: $_"
    exit 1
}

# Configure DNS Server
Write-Log "==== Configuring DNS Server ===="
try {
    Add-DnsServerPrimaryZone -Name $Domain -ZoneFile "db.$Domain" -ErrorAction Stop
    Add-DnsServerResourceRecordA -ZoneName $Domain -Name "@" -IPv4Address $IPInternet -ErrorAction Stop
    Add-DnsServerResourceRecordA -ZoneName $Domain -Name "ns1" -IPv4Address $IPInternet -ErrorAction Stop

    $existingForwarders = (Get-DnsServerForwarder).IPAddress
    $newForwarders = @("8.8.8.8", "1.1.1.1") | Where-Object { $_ -notin $existingForwarders }
    if ($newForwarders.Count -gt 0) {
        Set-DnsServerForwarder -IPAddress ($existingForwarders + $newForwarders) -ErrorAction Stop
        Write-Log "Updated DNS forwarders: $($existingForwarders + $newForwarders -join ', ')"
    }

    Set-DnsServerRecursion -Enable $true -ErrorAction Stop
    Restart-Service -Name DNS -ErrorAction Stop
    Write-Log "DNS Server configured and started."
}
catch {
    Write-Log "Error configuring DNS Server: $_"
    exit 1
}

# Configure File Sharing
Write-Log "==== Configuring File Sharing ===="
try {
    $groups = @("vanphong", "baove", "nhansu", "ketoan")
    foreach ($group in $groups) {
        if (-not (Get-LocalGroup -Name $group -ErrorAction SilentlyContinue)) {
            New-LocalGroup -Name $group -Description "Group for $group access" -ErrorAction Stop
            Write-Log "Created group: $group"
        }
    }

    $shareBase = "C:\Shares"
    $shares = @("vanphong", "baove", "nhansu", "ketoan")
    foreach ($share in $shares) {
        $path = Join-Path $shareBase $share
        New-Item -Path $path -ItemType Directory -Force -ErrorAction Stop | Out-Null

        $acl = Get-Acl -Path $path
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $share, "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($rule)
        Set-Acl -Path $path -AclObject $acl -ErrorAction Stop

        New-SmbShare -Name $share -Path $path -FullAccess $share -ErrorAction Stop
        Write-Log "Created share: $share at $path"
    }

    $users = @{
        "LinhKeToan" = "vanphong"
        "TaiNhanSu" = "vanphong"
        "ThienBaoVe" = "baove"
        "Nhanbaove" = "baove"
        "Nhannhansu" = "nhansu"
        "BaoKeToan" = "ketoan"
    }

    foreach ($user in $users.Keys) {
        if (-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue)) {
            $securePassword = ConvertTo-SecureString "123456" -AsPlainText -Force
            New-LocalUser -Name $user -Password $securePassword -FullName $user -Description "User $user" -ErrorAction Stop
            Add-LocalGroupMember -Group $users[$user] -Member $user -ErrorAction Stop
            Write-Log "Created user $user and added to group $($users[$user])."
        }
    }

    Restart-Service -Name LanmanServer -ErrorAction Stop
    Write-Log "File sharing configured and SMB service restarted."
}
catch {
    Write-Log "Error configuring file sharing: $_"
    exit 1
}

# Configure IP Forwarding and Firewall
Write-Log "==== Configuring IP Forwarding and Firewall ===="
try {
    foreach ($iface in @($InterfaceInternet, $InterfaceVanPhong, $InterfaceBaoVe)) {
        Set-NetIPInterface -InterfaceAlias $iface -Forwarding Enabled -ErrorAction Stop
        Write-Log "Enabled IP forwarding on $iface"
    }

    $firewallRules = @(
        @{Name="Allow DHCP"; Protocol="UDP"; LocalPort=67; Action="Allow"},
        @{Name="Allow DNS"; Protocol="TCP,UDP"; LocalPort=53; Action="Allow"},
        @{Name="Allow SMB"; Protocol="TCP"; LocalPort=445; Action="Allow"},
        @{Name="Allow Internet Interface"; InterfaceAlias=$InterfaceInternet; Action="Allow"},
        @{Name="Allow VanPhong Interface"; InterfaceAlias=$InterfaceVanPhong; Action="Allow"},
        @{Name="Allow BaoVe Interface"; InterfaceAlias=$InterfaceBaoVe; Action="Allow"}
    )

    foreach ($rule in $firewallRules) {
        $params = @{
            DisplayName = $rule.Name
            Direction = "Inbound"
            Action = $rule.Action
        }
        if ($rule.Protocol) { $params.Protocol = $rule.Protocol }
        if ($rule.LocalPort) { $params.LocalPort = $rule.LocalPort }
        if ($rule.InterfaceAlias) { $params.InterfaceAlias = $rule.InterfaceAlias }
        New-NetFirewallRule @params -ErrorAction Stop | Out-Null
        Write-Log "Created firewall rule: $($rule.Name)"
    }

    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop
    Write-Log "Firewall configured and enabled."
}
catch {
    Write-Log "Error configuring IP forwarding or firewall: $_"
    exit 1
}

# Finalize Setup
Write-Log "==== SETUP COMPLETED ===="
Write-Log "IP Internet : $IPInternet"
Write-Log "IP VanPhong : $IPVanPhong"
Write-Log "IP BaoVe    : $IPBaoVe"
Write-Log "Domain      : $Domain"
Write-Log "Users       : $($users.Keys -join ', ') (Password: 123456)"
Write-Log "Log File    : $LogFile"
Write-Log "=== SETUP FINISHED: $(Get-Date) ==="
