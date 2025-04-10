#!/bin/bash

# Cập nhật hệ thống
echo "Cập nhật hệ thống..."
sudo apt update && sudo apt upgrade -y

# Cài đặt DHCP server
echo "Cài đặt DHCP server..."
sudo apt install isc-dhcp-server -y
cat <<EOL | sudo tee /etc/dhcp/dhcpd.conf
subnet 192.168.1.0 netmask 255.255.255.0 {
  range 192.168.1.100 192.168.1.200;
  option routers 192.168.1.1;
  option domain-name-servers 192.168.1.10;
  option domain-name "toanha.local";
}
EOL
sudo sed -i 's/INTERFACESv4=""/INTERFACESv4="enp0s3"/' /etc/default/isc-dhcp-server
sudo systemctl restart isc-dhcp-server

# Cài đặt DNS server (bind9)
echo "Cài đặt DNS server..."
sudo apt install bind9 -y
cat <<EOL | sudo tee /etc/bind/named.conf.local
zone "toanha.local" {
  type master;
  file "/etc/bind/db.toanha.local";
};
EOL
cat <<EOL | sudo tee /etc/bind/db.toanha.local
\$TTL 604800
@ IN SOA toanha.local. root.toanha.local. (
  2         ; Serial
  604800    ; Refresh
  86400     ; Retry
  2419200   ; Expire
  604800 )  ; Negative Cache TTL
@ IN NS toanha.local.
@ IN A 192.168.1.10
server IN A 192.168.1.10
EOL
sudo systemctl restart bind9 || sudo systemctl restart named

# Cài đặt Samba để chia sẻ tệp
echo "Cài đặt Samba..."
sudo apt install samba -y
sudo mkdir -p /srv/share
sudo chmod 777 /srv/share
cat <<EOL | sudo tee -a /etc/samba/smb.conf
[public]
  path = /srv/share
  writable = yes
  browsable = yes
  guest ok = yes
EOL
sudo systemctl restart smbd

# Cấu hình firewall
echo "Cấu hình firewall..."
sudo ufw allow from 192.168.1.0/24
sudo ufw enable

# Gán IP tĩnh cho máy chủ
echo "Cấu hình IP tĩnh..."
cat <<EOL | sudo tee /etc/netplan/01-netcfg.yaml
network:
  version: 2
  ethernets:
    enp0s3:
      addresses:
        - 192.168.1.10/24
      nameservers:
        addresses: [192.168.1.10]
EOL
sudo chmod 644 /etc/netplan/01-netcfg.yaml
sudo netplan apply

echo "Cấu hình hoàn tất!"