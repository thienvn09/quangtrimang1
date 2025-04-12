#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
  echo "Hay chay script voi quyen root hoac sudo."
  exit 1
fi

# Cấu hình IP
INTERFACE_OFFICE="enp0s3"
INTERFACE_SECURITY="enp0s8"
IP_OFFICE="192.168.10.10"
IP_SECURITY="192.168.20.10"
NETMASK="24"
DOMAIN="toanha.local"
DNS_SERVER="$IP_OFFICE"

echo "==== Cap nhat he thong ===="
apt update && apt upgrade -y

echo "==== Cau hinh IP tinh cho hai interface ===="
cat <<EOF > /etc/netplan/01-netcfg.yaml
network:
  version: 2
  ethernets:
    $INTERFACE_OFFICE:
      addresses:
        - $IP_OFFICE/$NETMASK
      nameservers:
        addresses: [$DNS_SERVER]
    $INTERFACE_SECURITY:
      addresses:
        - $IP_SECURITY/$NETMASK
EOF

netplan apply

# === Cài DHCP ===
echo "==== Cai DHCP Server ===="
apt install isc-dhcp-server -y

cat <<EOF > /etc/dhcp/dhcpd.conf
subnet 192.168.10.0 netmask 255.255.255.0 {
  range 192.168.10.100 192.168.10.200;
  option routers 192.168.10.10;
  option domain-name-servers $DNS_SERVER;
  option domain-name "$DOMAIN";
}
subnet 192.168.20.0 netmask 255.255.255.0 {
  range 192.168.20.100 192.168.20.200;
  option routers 192.168.20.10;
  option domain-name-servers $DNS_SERVER;
  option domain-name "$DOMAIN";
}
EOF

sed -i "s/^INTERFACESv4=.*/INTERFACESv4=\"$INTERFACE_OFFICE $INTERFACE_SECURITY\"/" /etc/default/isc-dhcp-server
systemctl restart isc-dhcp-server
systemctl enable isc-dhcp-server

# === DNS Server (Bind9) ===
echo "==== Cai DNS (BIND9) ===="
apt install bind9 -y

cat <<EOF > /etc/bind/named.conf.local
zone "$DOMAIN" {
  type master;
  file "/etc/bind/db.$DOMAIN";
};
EOF

cat <<EOF > /etc/bind/db.$DOMAIN
\$TTL 604800
@ IN SOA $DOMAIN. root.$DOMAIN. (
  3         ; Serial
  604800    ; Refresh
  86400     ; Retry
  2419200   ; Expire
  604800 )  ; Negative Cache TTL
@ IN NS $DOMAIN.
@ IN A $IP_OFFICE
server IN A $IP_OFFICE
EOF

cat <<EOF > /etc/bind/named.conf.options
options {
  directory "/var/cache/bind";
  dnssec-validation no;
  listen-on port 53 { any; };
  allow-query { any; };
};
EOF

named-checkconf
named-checkzone "$DOMAIN" /etc/bind/db.$DOMAIN
systemctl restart bind9
systemctl enable bind9

# === Samba Setup ===
echo "==== Cai dat Samba ===="
apt install samba -y

# Tạo nhóm và thư mục chia sẻ theo tầng
groupadd -f office
groupadd -f security

mkdir -p /srv/share/office
mkdir -p /srv/share/security

chown root:office /srv/share/office
chown root:security /srv/share/security

chmod 2770 /srv/share/office
chmod 2770 /srv/share/security

# Tạo user mẫu cho mỗi tầng
useradd -m -s /bin/bash vanphong1
useradd -m -s /bin/bash vanphong2
useradd -m -s /bin/bash baove1
useradd -m -s /bin/bash baove2

# Gán group
usermod -aG office vanphong1
usermod -aG office vanphong2
usermod -aG security baove1
usermod -aG security baove2

# Đặt mật khẩu Samba
echo -e "123456\n123456" | smbpasswd -a vanphong1
echo -e "123456\n123456" | smbpasswd -a vanphong2
echo -e "123456\n123456" | smbpasswd -a baove1
echo -e "123456\n123456" | smbpasswd -a baove2

cat <<EOF >> /etc/samba/smb.conf

[Office]
   path = /srv/share/office
   writable = yes
   browsable = yes
   valid users = @office
   create mask = 0660
   directory mask = 2770
   force group = office

[Security]
   path = /srv/share/security
   writable = yes
   browsable = yes
   valid users = @security
   create mask = 0660
   directory mask = 2770
   force group = security
EOF

systemctl restart smbd
systemctl enable smbd

# === UFW ===
ufw allow from 192.168.10.0/24
ufw allow from 192.168.20.0/24
ufw allow 67/udp
ufw allow 53
ufw allow 'Samba'
ufw --force enable

echo "==== CAU HINH HOAN TAT ===="
echo "IP Office: $IP_OFFICE"
echo "IP Security: $IP_SECURITY"
echo "Domain noi bo: $DOMAIN"
echo "Thu muc Office: /srv/share/office"
echo "Thu muc Security: /srv/share/security"
