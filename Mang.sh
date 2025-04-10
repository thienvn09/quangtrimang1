#!/bin/bash

# Thoát nếu có lỗi
set -e

# Kiểm tra quyền sudo
if [ "$EUID" -ne 0 ]; then
  echo "Vui lòng chạy script với quyền root hoặc sudo."
  exit 1
fi

# Biến cấu hình
IP_STATIC="192.168.1.10"
NETMASK="24"
GATEWAY="192.168.1.1"
DNS_SERVER="$IP_STATIC"
INTERFACE=$(ip -o -4 route show to default | awk '{print $5}')
DOMAIN="toanha.local"
SHARE_DIR="/srv/share"

echo "==== Cập nhật hệ thống ===="
apt update && apt upgrade -y

echo "==== Cấu hình địa chỉ IP tĩnh ===="
cat <<EOL > /etc/netplan/01-netcfg.yaml
network:
  version: 2
  ethernets:
    $INTERFACE:
      addresses:
        - $IP_STATIC/$NETMASK
      gateway4: $GATEWAY
      nameservers:
        addresses: [$DNS_SERVER, 8.8.8.8]
EOL

netplan apply
echo "Đã cấu hình IP tĩnh cho interface: $INTERFACE"

echo "==== Cài đặt DHCP Server ===="
apt install isc-dhcp-server -y

# Cấu hình DHCP
cat <<EOL > /etc/dhcp/dhcpd.conf
subnet 192.168.1.0 netmask 255.255.255.0 {
  range 192.168.1.100 192.168.1.200;
  option routers $GATEWAY;
  option domain-name-servers $DNS_SERVER;
  option domain-name "$DOMAIN";
}
EOL

# Chỉ định interface cho DHCP
sed -i "s/^INTERFACESv4=.*/INTERFACESv4=\"$INTERFACE\"/" /etc/default/isc-dhcp-server
systemctl restart isc-dhcp-server
systemctl enable isc-dhcp-server

echo "==== Cài đặt DNS Server (BIND9) ===="
apt install bind9 -y

# Tạo zone DNS
cat <<EOL > /etc/bind/named.conf.local
zone "$DOMAIN" {
  type master;
  file "/etc/bind/db.$DOMAIN";
};
EOL

cat <<EOL > /etc/bind/db.$DOMAIN
\$TTL 604800
@ IN SOA $DOMAIN. root.$DOMAIN. (
  2         ; Serial
  604800    ; Refresh
  86400     ; Retry
  2419200   ; Expire
  604800 )  ; Negative Cache TTL
@ IN NS $DOMAIN.
@ IN A $IP_STATIC
server IN A $IP_STATIC
EOL

named-checkconf
named-checkzone "$DOMAIN" /etc/bind/db.$DOMAIN
systemctl restart bind9
systemctl enable bind9

echo "==== Cài đặt Samba ===="
apt install samba -y

mkdir -p $SHARE_DIR
chmod 777 $SHARE_DIR

# Cấu hình chia sẻ công khai
cat <<EOL >> /etc/samba/smb.conf

[public]
   path = $SHARE_DIR
   writable = yes
   browsable = yes
   guest ok = yes
EOL

systemctl restart smbd
systemctl enable smbd

echo "==== Cấu hình tường lửa (UFW) ===="
ufw allow from 192.168.1.0/24
ufw allow 67/udp     # DHCP
ufw allow 53         # DNS
ufw allow 'Samba'    # Mở các cổng 137-139, 445
ufw --force enable

echo "==== Hoàn tất cấu hình máy chủ nội bộ ===="
echo "🟢 IP máy chủ: $IP_STATIC"
echo "🟢 Samba chia sẻ thư mục: $SHARE_DIR"
echo "🟢 Domain nội bộ: $DOMAIN"
