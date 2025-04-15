#!/bin/bash
set -e

# ========================
# Bien cau hinh
# ========================
INTERFACE_INTERNET="enp0s3"
INTERFACE_VANPHONG="enp0s8"
INTERFACE_BAOVE="enp0s9"
IP_INTERNET="192.168.100.10"
IP_VANPHONG="192.168.10.10"
IP_BAOVE="192.168.20.10"
NETMASK="24"
DOMAIN="toanha.local"
DNS_SERVER="$IP_INTERNET"
LOG_FILE="/root/setup_log.txt"

# ========================
# Kiem tra quyen root
# ========================
if [ "$EUID" -ne 0 ]; then
  echo "  Hay chay script voi quyen root hoac sudo."
  exit 1
fi

# ========================
# Tao file log
# ========================
touch $LOG_FILE
echo "=== BAT DAU CAI DAT: $(date) ===" | tee -a $LOG_FILE

# ========================
# Kiem tra giao dien mang
# ========================
echo "==== Kiem tra giao dien mang ===="
for iface in $INTERFACE_INTERNET $INTERFACE_VANPHONG $INTERFACE_BAOVE; do
  if ! ip link show $iface > /dev/null 2>&1; then
    echo " Giao dien $iface khong ton tai." | tee -a $LOG_FILE
    exit 1
  fi
done

# ========================
# Cau hinh IP tinh voi Netplan
# ========================
echo "==== Cau hinh IP tinh ===="

cat <<EOF > /etc/netplan/01-netcfg.yaml
network:
  version: 2
  ethernets:
    $INTERFACE_INTERNET:
      addresses: [$IP_INTERNET/$NETMASK]
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
      dhcp4: no
    $INTERFACE_VANPHONG:
      addresses: [$IP_VANPHONG/$NETMASK]
      dhcp4: no
    $INTERFACE_BAOVE:
      addresses: [$IP_BAOVE/$NETMASK]
      dhcp4: no
EOF

chmod 600 /etc/netplan/01-netcfg.yaml
echo "Ap dung netplan..." | tee -a $LOG_FILE
if netplan apply >> $LOG_FILE 2>&1; then
  echo " Netplan da duoc ap dung." | tee -a $LOG_FILE
else
  echo " Loi netplan. Kiem tra $LOG_FILE" | tee -a $LOG_FILE
  exit 1
fi

# ========================
# Kiem tra ket noi Internet
# ========================
echo "==== Kiem tra ket noi Internet ===="
if ping -c 1 8.8.8.8 > /dev/null 2>&1; then
  echo " Ket noi Internet OK." | tee -a $LOG_FILE
else
  echo " Khong co ket noi Internet. Kiem tra NAT va DNS." | tee -a $LOG_FILE
  exit 1
fi

# ========================
# Cap nhat he thong
# ========================
echo "==== Cap nhat he thong ===="
apt update >> $LOG_FILE 2>&1 && apt upgrade -y >> $LOG_FILE 2>&1 || {
  echo "Loi cap nhat he thong." | tee -a $LOG_FILE
  exit 1
}

# ========================
# Cai dat DHCP Server
# ========================
echo "==== Cai dat DHCP Server ===="
apt install isc-dhcp-server -y >> $LOG_FILE 2>&1 || {
  echo " Loi cai DHCP." | tee -a $LOG_FILE
  exit 1
}

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

echo "INTERFACESv4=\"$INTERFACE_VANPHONG $INTERFACE_BAOVE\"" > /etc/default/isc-dhcp-server

systemctl restart isc-dhcp-server >> $LOG_FILE 2>&1 && systemctl enable isc-dhcp-server >> $LOG_FILE 2>&1 || {
  echo " DHCP server loi khi khoi dong." | tee -a $LOG_FILE
  exit 1
}

# ========================
# Cai dat Bind9 DNS
# ========================
echo "==== Cai dat DNS Server ===="
apt install bind9 -y >> $LOG_FILE 2>&1 || {
  echo " Loi cai Bind9." | tee -a $LOG_FILE
  exit 1
}

cat <<EOF > /etc/bind/named.conf.local
zone "$DOMAIN" {
  type master;
  file "/etc/bind/db.$DOMAIN";
};
EOF

cat <<EOF > /etc/bind/db.$DOMAIN
\$TTL 604800
@ IN SOA $DOMAIN. root.$DOMAIN. (
  2         ; Serial
  604800    ; Refresh
  86400     ; Retry
  2419200   ; Expire
  604800 )  ; Negative Cache TTL
@ IN NS server.$DOMAIN.
@ IN A $IP_INTERNET
server IN A $IP_INTERNET
EOF

cat <<EOF > /etc/bind/named.conf.options
options {
  directory "/var/cache/bind";
  dnssec-validation no;
  listen-on port 53 { any; };
  allow-query { any; };
};
EOF

chmod 644 /etc/bind/named.conf.local /etc/bind/db.$DOMAIN /etc/bind/named.conf.options

named-checkconf >> $LOG_FILE 2>&1 && named-checkzone "$DOMAIN" /etc/bind/db.$DOMAIN >> $LOG_FILE 2>&1 || {
  echo " Loi cau hinh DNS." | tee -a $LOG_FILE
  exit 1
}

systemctl restart bind9 >> $LOG_FILE 2>&1 && systemctl enable bind9 >> $LOG_FILE 2>&1 || {
  echo " Loi khoi dong Bind9." | tee -a $LOG_FILE
  exit 1
}

# ========================
# Cai dat Samba va nguoi dung
# ========================
echo "==== Cai dat Samba ===="
apt install samba -y >> $LOG_FILE 2>&1 || {
  echo " Loi cai dat Samba." | tee -a $LOG_FILE
  exit 1
}

groupadd -f vanphong && groupadd -f baove && groupadd -f nhansu && groupadd -f ketoan
mkdir -p /srv/share/{vanphong,baove,nhansu,ketoan}
chown root:vanphong /srv/share/vanphong
chown root:baove /srv/share/baove
chown root:nhansu /srv/share/nhansu
chown root:ketoan /srv/share/ketoan
chmod 2770 /srv/share/*

# Tao nguoi dung va gan nhom
declare -A USERS=(
  ["LinhKeToan"]="vanphong"
  ["TaiNhanSu"]="vanphong"
  ["ThienBaoVe"]="baove"
  ["Nhanbaove"]="baove"
  ["Nhannhansu"]="nhansu"
  ["BaoKeToan"]="ketoan"
)

for user in "${!USERS[@]}"; do
  useradd -m -s /bin/bash "$user"
  usermod -aG "${USERS[$user]}" "$user"
  echo -e "123456\n123456" | smbpasswd -a "$user" >> $LOG_FILE 2>&1
done

cat <<EOF >> /etc/samba/smb.conf
[VanPhong]
   path = /srv/share/vanphong
   valid users = @vanphong
   writable = yes
   browsable = yes
   create mask = 0660
   directory mask = 2770
   force group = vanphong

[BaoVe]
   path = /srv/share/baove
   valid users = @baove
   writable = yes
   browsable = yes
   create mask = 0660
   directory mask = 2770
   force group = baove

[NhanSu]
   path = /srv/share/nhansu
   valid users = @nhansu
   writable = yes
   browsable = yes
   create mask = 0660
   directory mask = 2770
   force group = nhansu

[KeToan]
   path = /srv/share/ketoan
   valid users = @ketoan
   writable = yes
   browsable = yes
   create mask = 0660
   directory mask = 2770
   force group = ketoan
EOF

systemctl restart smbd >> $LOG_FILE 2>&1 && systemctl enable smbd >> $LOG_FILE 2>&1 || {
  echo " Loi khoi dong Samba." | tee -a $LOG_FILE
  exit 1
}

# ========================
# Bat IP Forward va Firewall
# ========================
echo "==== Cau hinh dinh tuyen va Firewall ===="
sysctl -w net.ipv4.ip_forward=1 >> $LOG_FILE
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

ufw allow in on $INTERFACE_INTERNET
ufw allow in on $INTERFACE_VANPHONG
ufw allow in on $INTERFACE_BAOVE
ufw allow out on $INTERFACE_INTERNET
ufw allow out on $INTERFACE_VANPHONG
ufw allow out on $INTERFACE_BAOVE

ufw allow 67/udp
ufw allow 53/udp
ufw allow 53/tcp
ufw allow 'Samba'
ufw --force enable

# ========================
# Hoan tat
# ========================
echo "==== CAI DAT HOAN TAT ====" | tee -a $LOG_FILE
echo "IP Internet (Card1): $IP_INTERNET" | tee -a $LOG_FILE
echo "IP VanPhong (Card2): $IP_VANPHONG" | tee -a $LOG_FILE
echo "IP BaoVe (Card3): $IP_BAOVE" | tee -a $LOG_FILE
echo "DOMAIN noi bo: $DOMAIN" | tee -a $LOG_FILE
echo "Nguoi dung: ${!USERS[@]} (pass: 123456)" | tee -a $LOG_FILE
echo "Thong tin log tai $LOG_FILE" | tee -a $LOG_FILE
echo "=== HOAN TAT CAI DAT: $(date) ===" | tee -a $LOG_FILE