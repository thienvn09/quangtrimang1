#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
  echo "Hay chay script voi quyen root hoac sudo."
  exit 1
fi

# Cấu hình mạng
INTERFACE_VANPHONG="enp0s3"
INTERFACE_BAOVE="enp0s8"
IP_VANPHONG="192.168.10.10"
IP_BAOVE="192.168.20.10"
NETMASK="24"
DOMAIN="toanha.local"
DNS_SERVER="$IP_VANPHONG"

echo "==== Cap nhat he thong ===="
apt update && apt upgrade -y

echo "==== Cau hinh IP tinh cho 2 interface ===="
cat <<EOF > /etc/netplan/01-netcfg.yaml
network:
  version: 2
  ethernets:
    $INTERFACE_VANPHONG:
      addresses:
        - $IP_VANPHONG/$NETMASK
      nameservers:
        addresses: [$DNS_SERVER]
    $INTERFACE_BAOVE:
      addresses:
        - $IP_BAOVE/$NETMASK
EOF

netplan apply

echo "==== Cai DHCP Server ===="
apt install isc-dhcp-server -y

cat <<EOF > /etc/dhcp/dhcpd.conf
subnet 192.168.10.0 netmask 255.255.255.0 {
  range 192.168.10.100 192.168.10.200;
  option routers $IP_VANPHONG;
  option domain-name-servers $DNS_SERVER;
  option domain-name "$DOMAIN";
}

subnet 192.168.20.0 netmask 255.255.255.0 {
  range 192.168.20.100 192.168.20.200;
  option routers $IP_BAOVE;
  option domain-name-servers $DNS_SERVER;
  option domain-name "$DOMAIN";
}
EOF

sed -i "s/^INTERFACESv4=.*/INTERFACESv4=\"$INTERFACE_VANPHONG $INTERFACE_BAOVE\"/" /etc/default/isc-dhcp-server
systemctl restart isc-dhcp-server
systemctl enable isc-dhcp-server

echo "==== Cai DNS (Bind9) ===="
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
@ IN A $IP_VANPHONG
server IN A $IP_VANPHONG
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

echo "==== Cai dat Samba ===="
apt install samba -y

# Tạo nhóm chia sẻ
groupadd -f vanphong
groupadd -f baove
groupadd -f nhansu
groupadd -f ketoan

# Tạo thư mục chia sẻ
mkdir -p /srv/share/vanphong
mkdir -p /srv/share/baove
mkdir -p /srv/share/nhansu
mkdir -p /srv/share/ketoan

# Phân quyền thư mục
chown root:vanphong /srv/share/vanphong
chown root:baove /srv/share/baove
chown root:nhansu /srv/share/nhansu
chown root:ketoan /srv/share/ketoan

chmod 2770 /srv/share/vanphong
chmod 2770 /srv/share/baove
chmod 2770 /srv/share/nhansu
chmod 2770 /srv/share/ketoan

# Tạo người dùng và gán nhóm
useradd -m -s /bin/bash LinhKeToan
useradd -m -s /bin/bash TaiNhanSu
useradd -m -s /bin/bash ThienBaoVe
useradd -m -s /bin/bash Nhanbaove
useradd -m -s /bin/bash Nhannhansu
useradd -m -s /bin/bash BaoKeToan

# Gán người dùng vào nhóm
usermod -aG vanphong LinhKeToan
usermod -aG vanphong TaiNhanSu
usermod -aG baove ThienBaoVe
usermod -aG baove Nhanbaove
usermod -aG nhansu Nhannhansu
usermod -aG ketoan BaoKeToan

# Đặt mật khẩu Samba cho người dùng
for user in LinhKeToan TaiNhanSu ThienBaoVe Nhanbaove Nhannhansu BaoKeToan; do
  echo -e "123456\n123456" | smbpasswd -a $user
done

# Cấu hình chia sẻ Samba
cat <<EOF >> /etc/samba/smb.conf

[VanPhong]
   path = /srv/share/vanphong
   writable = yes
   browsable = yes
   valid users = @vanphong
   create mask = 0660
   directory mask = 2770
   force group = vanphong

[BaoVe]
   path = /srv/share/baove
   writable = yes
   browsable = yes
   valid users = @baove
   create mask = 0660
   directory mask = 2770
   force group = baove

[NhanSu]
   path = /srv/share/nhansu
   writable = yes
   browsable = yes
   valid users = @nhansu
   create mask = 0660
   directory mask = 2770
   force group = nhansu

[KeToan]
   path = /srv/share/ketoan
   writable = yes
   browsable = yes
   valid users = @ketoan
   create mask = 0660
   directory mask = 2770
   force group = ketoan
EOF

systemctl restart smbd
systemctl enable smbd

echo "==== Cau hinh tuong lua (UFW) ===="
ufw allow from 192.168.10.0/24
ufw allow from 192.168.20.0/24
ufw allow 67/udp
ufw allow 53
ufw allow 'Samba'
ufw --force enable

echo "==== CAU HINH HOAN TAT ===="
echo "IP vanphong: $IP_VANPHONG"
echo "IP baove: $IP_BAOVE"
echo "Ten mien noi bo: $DOMAIN"
echo "Thu muc chia se: "
echo " - VanPhong: /srv/share/vanphong"
echo " - BaoVe: /srv/share/baove"
echo " - NhanSu: /srv/share/nhansu"
echo " - KeToan: /srv/share/ketoan"
echo "User mac dinh: LinhKeToan, TaiNhanSu, ThienBaoVe, Nhanbaove, Nhannhansu, BaoKeToan (mat khau: 123456)"
