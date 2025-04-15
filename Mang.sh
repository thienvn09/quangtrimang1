#!/bin/bash
set -e

# Kiem tra quyen root
if [ "$EUID" -ne 0 ]; then
  echo "Hay chay script voi quyen root hoac sudo."
  exit 1
fi

# Bien cau hinh
INTERFACE_VANPHONG="enp0s3"
INTERFACE_BAOVE="enp0s8"
IP_VANPHONG="192.168.10.10"
IP_BAOVE="192.168.20.10"
NETMASK="24"
DOMAIN="toanha.local"
DNS_SERVER="$IP_VANPHONG"
LOG_FILE="/root/setup_log.txt"

# Tao file log
touch $LOG_FILE
echo "Bat dau cau hinh: $(date)" >> $LOG_FILE

# Kiem tra giao dien mang
echo "==== Kiem tra giao dien mang ===="
if ! ip link show $INTERFACE_VANPHONG > /dev/null || ! ip link show $INTERFACE_BAOVE > /dev/null; then
  echo "Giao dien $INTERFACE_VANPHONG hoac $INTERFACE_BAOVE khong ton tai." | tee -a $LOG_FILE
  exit 1
fi

# Cap nhat he thong
echo "==== Cap nhat he thong ===="
if ! ping -c 1 8.8.8.8 > /dev/null 2>&1; then
  echo "Khong co ket noi mang. Vui long kiem tra:" | tee -a $LOG_FILE
  echo "1. Dam bao may ao duoc cau hinh mang (NAT hoac Bridged)." | tee -a $LOG_FILE
  echo "2. Kiem tra ket noi Internet tren may chu (host)." | tee -a $LOG_FILE
  echo "3. Them DNS bang lenh: echo 'nameserver 8.8.8.8' | sudo tee -a /etc/resolv.conf" | tee -a $LOG_FILE
  exit 1
fi
apt update >> $LOG_FILE 2>&1
apt upgrade -y >> $LOG_FILE 2>&1

# Cau hinh IP tinh
echo "==== Cau hinh IP tinh cho 2 giao dien ===="
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

chmod 600 /etc/netplan/01-netcfg.yaml
netplan apply >> $LOG_FILE 2>&1
if [ $? -ne 0 ]; then
  echo "Loi khi ap dung cau hinh mang. Kiem tra log tai $LOG_FILE." | tee -a $LOG_FILE
  exit 1
fi
echo "Da ap dung cau hinh mang." >> $LOG_FILE

# DHCP Server
echo "==== Cai dat DHCP Server ===="
apt install isc-dhcp-server -y >> $LOG_FILE 2>&1

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

# Giao dien cho DHCP
if ! grep -q "^INTERFACESv4=" /etc/default/isc-dhcp-server; then
  echo "INTERFACESv4=\"$INTERFACE_VANPHONG $INTERFACE_BAOVE\"" >> /etc/default/isc-dhcp-server
else
  sed -i "s/^INTERFACESv4=.*/INTERFACESv4=\"$INTERFACE_VANPHONG $INTERFACE_BAOVE\"/" /etc/default/isc-dhcp-server
fi

systemctl restart isc-dhcp-server >> $LOG_FILE 2>&1
systemctl enable isc-dhcp-server >> $LOG_FILE 2>&1
systemctl status isc-dhcp-server >> $LOG_FILE 2>&1
if [ $? -ne 0 ]; then
  echo "Loi khoi dong DHCP Server. Kiem tra log tai $LOG_FILE." | tee -a $LOG_FILE
  exit 1
fi
echo "DHCP Server da duoc cau hinh." >> $LOG_FILE

# Bind9 DNS
echo "==== Cai dat DNS (Bind9) ===="
apt install bind9 -y >> $LOG_FILE 2>&1

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
@ IN NS server.$DOMAIN.
@ IN A $IP_VANPHONG
server IN A $IP_VANPHONG
EOF

cat <<EOF > /etc/bind/named.conf.options
options {
  directory "/var/cache/bind";
  dnssec-validation no;
  listen-on port 53 { any; };
  listen-on-v6 port 53 { any; };
  allow-query { any; };
};
EOF

chmod 644 /etc/bind/named.conf.local
chmod 644 /etc/bind/db.$DOMAIN
chmod 644 /etc/bind/named.conf.options

named-checkconf >> $LOG_FILE 2>&1
named-checkzone "$DOMAIN" /etc/bind/db.$DOMAIN >> $LOG_FILE 2>&1
if [ $? -ne 0 ]; then
  echo "Loi cau hinh DNS. Kiem tra log tai $LOG_FILE." | tee -a $LOG_FILE
  exit 1
fi

systemctl restart bind9 >> $LOG_FILE 2>&1
systemctl enable bind9 >> $LOG_FILE 2>&1
systemctl status bind9 >> $LOG_FILE 2>&1
if [ $? -ne 0 ]; then
  echo "Loi khoi dong DNS Server. Kiem tra log tai $LOG_FILE." | tee -a $LOG_FILE
  exit 1
fi
echo "DNS Server da duoc cau hinh." >> $LOG_FILE

# Samba
echo "==== Cai dat Samba ===="
apt install samba -y >> $LOG_FILE 2>&1

groupadd -f vanphong
groupadd -f baove
groupadd -f nhansu
groupadd -f ketoan

mkdir -p /srv/share/vanphong /srv/share/baove /srv/share/nhansu /srv/share/ketoan

chown root:vanphong /srv/share/vanphong
chown root:baove /srv/share/baove
chown root:nhansu /srv/share/nhansu
chown root:ketoan /srv/share/ketoan

chmod 2770 /srv/share/*

useradd -m -s /bin/bash LinhKeToan
useradd -m -s /bin/bash TaiNhanSu
useradd -m -s /bin/bash ThienBaoVe
useradd -m -s /bin/bash Nhanbaove
useradd -m -s /bin/bash Nhannhansu
useradd -m -s /bin/bash BaoKeToan

usermod -aG vanphong LinhKeToan
usermod -aG vanphong TaiNhanSu
usermod -aG baove ThienBaoVe
usermod -aG baove Nhanbaove
usermod -aG nhansu Nhannhansu
usermod -aG ketoan BaoKeToan

for user in LinhKeToan TaiNhanSu ThienBaoVe Nhanbaove Nhannhansu BaoKeToan; do
  echo -e "123456\n123456" | smbpasswd -a $user >> $LOG_FILE 2>&1
done

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

systemctl restart smbd >> $LOG_FILE 2>&1
systemctl enable smbd >> $LOG_FILE 2>&1
systemctl status smbd >> $LOG_FILE 2>&1
if [ $? -ne 0 ]; then
  echo "Loi khoi dong Samba. Kiem tra log tai $LOG_FILE." | tee -a $LOG_FILE
  exit 1
fi
echo "Samba da duoc cau hinh." >> $LOG_FILE

# Routing giua 2 mang
echo "==== Cau hinh dinh tuyen giua hai mang ===="
sysctl -w net.ipv4.ip_forward=1 >> $LOG_FILE 2>&1
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
ufw allow in on $INTERFACE_VANPHONG to any >> $LOG_FILE 2>&1
ufw allow in on $INTERFACE_BAOVE to any >> $LOG_FILE 2>&1
ufw allow out on $INTERFACE_VANPHONG to any >> $LOG_FILE 2>&1
ufw allow out on $INTERFACE_BAOVE to any >> $LOG_FILE 2>&1
echo "Da cau hinh dinh tuyen." >> $LOG_FILE

# Tuong lua (UFW)
echo "==== Cau hinh tuong lua (UFW) ===="
ufw default deny incoming >> $LOG_FILE 2>&1
ufw default allow outgoing >> $LOG_FILE 2>&1
ufw allow from 192.168.10.0/24 >> $LOG_FILE 2>&1
ufw allow from 192.168.20.0/24 >> $LOG_FILE 2>&1
ufw allow 67/udp >> $LOG_FILE 2>&1
ufw allow 53/udp >> $LOG_FILE 2>&1
ufw allow 53/tcp >> $LOG_FILE 2>&1
ufw allow 'Samba' >> $LOG_FILE 2>&1
ufw --force enable >> $LOG_FILE 2>&1
echo "Tuong lua da duoc cau hinh." >> $LOG_FILE

# Hoan tat
echo "==== CAU HINH HOAN TAT ====" | tee -a $LOG_FILE
echo "IP van phong: $IP_VANPHONG" | tee -a $LOG_FILE
echo "IP bao ve: $IP_BAOVE" | tee -a $LOG_FILE
echo "Ten mien noi bo: $DOMAIN" | tee -a $LOG_FILE
echo "Thu muc chia se:" | tee -a $LOG_FILE
echo " - Van phong: /srv/share/vanphong" | tee -a $LOG_FILE
echo " - Bao ve: /srv/share/baove" | tee -a $LOG_FILE
echo " - Nhan su: /srv/share/nhansu" | tee -a $LOG_FILE
echo " - Ke toan: /srv/share/ketoan" | tee -a $LOG_FILE
echo "Nguoi dung mac dinh: LinhKeToan, TaiNhanSu, ThienBaoVe, Nhanbaove, Nhannhansu, BaoKeToan (mat khau: 123456)" | tee -a $LOG_FILE
echo "Kiem tra chi tiet tai $LOG_FILE" | tee -a $LOG_FILE
