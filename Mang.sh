#!/bin/bash

# Dung script neu co loi
set -e

# Kiem tra quyen root
if [ "$EUID" -ne 0 ]; then
  echo "Hay chay script voi quyen root hoac sudo."
  exit 1
fi

# Bien cau hinh
IP_STATIC="192.168.1.10"
NETMASK="24"
DNS_SERVER="$IP_STATIC"
INTERFACE="enp0s3"
DOMAIN="toanha.local"
SHARE_DIR="/srv/share"
SHARE_GROUP="sambashare"

echo "==== Cap nhat he thong ===="
apt update && apt upgrade -y

echo "==== Cau hinh dia chi IP tinh ===="
cat <<EOL > /etc/netplan/01-netcfg.yaml
network:
  version: 2
  ethernets:
    $INTERFACE:
      addresses:
        - $IP_STATIC/$NETMASK
      nameservers:
        addresses: [$DNS_SERVER]
EOL

chmod 644 /etc/netplan/01-netcfg.yaml
netplan apply
echo "Da cau hinh IP tinh cho interface: $INTERFACE"

echo "==== Cai dat DHCP server ===="
apt install isc-dhcp-server -y

cat <<EOL > /etc/dhcp/dhcpd.conf
subnet 192.168.1.0 netmask 255.255.255.0 {
  range 192.168.1.100 192.168.1.200;
  option domain-name-servers $DNS_SERVER;
  option domain-name "$DOMAIN";
}
EOL

sed -i "s/^INTERFACESv4=.*/INTERFACESv4=\"$INTERFACE\"/" /etc/default/isc-dhcp-server
systemctl restart isc-dhcp-server
systemctl enable isc-dhcp-server

echo "==== Cai dat DNS server (BIND9) ===="
apt install bind9 -y

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

cat <<EOL > /etc/bind/named.conf.options
options {
  directory "/var/cache/bind";
  dnssec-validation no;
  listen-on port 53 { any; };
  allow-query { any; };
};
EOL

named-checkconf
named-checkzone "$DOMAIN" /etc/bind/db.$DOMAIN
systemctl restart bind9
systemctl enable bind9

echo "==== Cai dat Samba ===="
apt install samba -y

groupadd -f $SHARE_GROUP
mkdir -p $SHARE_DIR
chown root:$SHARE_GROUP $SHARE_DIR
chmod 2770 $SHARE_DIR

usermod -aG $SHARE_GROUP nobody

cat <<EOL >> /etc/samba/smb.conf

[public]
   path = $SHARE_DIR
   writable = yes
   browsable = yes
   guest ok = yes
   create mask = 0660
   directory mask = 2770
   force group = $SHARE_GROUP
EOL

systemctl restart smbd
systemctl enable smbd

echo "==== Cau hinh tuong lua (UFW) ===="
ufw allow from 192.168.1.0/24
ufw allow 67/udp
ufw allow 53
ufw allow 'Samba'
ufw --force enable

echo "==== Hoan tat cau hinh may chu noi bo ===="
echo "Dia chi IP: $IP_STATIC"
echo "Thu muc chia se Samba: $SHARE_DIR"
echo "Ten mien noi bo: $DOMAIN"
