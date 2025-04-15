#!/bin/bash
set -e

# Kiểm tra quyền root
if [ "$EUID" -ne 0 ]; then
  echo "Hãy chạy script với quyền root hoặc sudo."
  exit 1
fi

# Biến cấu hình
INTERFACE_VANPHONG="enp0s3" # Card mạng văn phòng
INTERFACE_BAOVE="enp0s8"    # Card mạng bảo vệ
IP_VANPHONG="192.168.10.10" # IP tĩnh cho văn phòng
IP_BAOVE="192.168.20.10"    # IP tĩnh cho bảo vệ
NETMASK="24"                # Subnet mask
DOMAIN="toanha.local"       # Tên miền nội bộ
DNS_SERVER="$IP_VANPHONG"   # DNS server là IP văn phòng
LOG_FILE="/root/setup_log.txt" # File log để ghi lại quá trình cấu hình

# Tạo file log
touch $LOG_FILE
echo "Bắt đầu cấu hình: $(date)" >> $LOG_FILE

# Kiểm tra giao diện mạng
echo "==== Kiểm tra giao diện mạng ===="
if ! ip link show $INTERFACE_VANPHONG > /dev/null || ! ip link show $INTERFACE_BAOVE > /dev/null; then
  echo "Giao diện $INTERFACE_VANPHONG hoặc $INTERFACE_BAOVE không tồn tại." | tee -a $LOG_FILE
  exit 1
fi

# Cập nhật hệ thống
echo "==== Cập nhật hệ thống ===="
if ! ping -c 1 8.8.8.8 > /dev/null 2>&1; then
  echo "Không có kết nối mạng. Vui lòng kiểm tra:" | tee -a $LOG_FILE
  echo "1. Đảm bảo máy ảo được cấu hình mạng (NAT hoặc Bridged)." | tee -a $LOG_FILE
  echo "2. Kiểm tra kết nối Internet trên máy chủ (host)." | tee -a $LOG_FILE
  echo "3. Thêm DNS bằng lệnh: echo 'nameserver 8.8.8.8' | sudo tee -a /etc/resolv.conf" | tee -a $LOG_FILE
  exit 1
fi
apt update >> $LOG_FILE 2>&1
apt upgrade -y >> $LOG_FILE 2>&1

# Cấu hình IP tĩnh cho 2 giao diện
echo "==== Cấu hình IP tĩnh cho 2 giao diện ===="
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

# Đặt quyền cho file Netplan
chmod 600 /etc/netplan/01-netcfg.yaml
netplan apply >> $LOG_FILE 2>&1
if [ $? -ne 0 ]; then
  echo "Lỗi khi áp dụng cấu hình mạng. Kiểm tra log tại $LOG_FILE." | tee -a $LOG_FILE
  exit 1
fi
echo "Đã áp dụng cấu hình mạng." >> $LOG_FILE

# Cài đặt và cấu hình DHCP Server
echo "==== Cài đặt DHCP Server ===="
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

# Cấu hình giao diện cho DHCP
if ! grep -q "^INTERFACESv4=" /etc/default/isc-dhcp-server; then
  echo "INTERFACESv4=\"$INTERFACE_VANPHONG $INTERFACE_BAOVE\"" >> /etc/default/isc-dhcp-server
else
  sed -i "s/^INTERFACESv4=.*/INTERFACESv4=\"$INTERFACE_VANPHONG $INTERFACE_BAOVE\"/" /etc/default/isc-dhcp-server
fi

systemctl restart isc-dhcp-server >> $LOG_FILE 2>&1
systemctl enable isc-dhcp-server >> $LOG_FILE 2>&1
# Kiểm tra trạng thái DHCP
systemctl status isc-dhcp-server >> $LOG_FILE 2>&1
if [ $? -ne 0 ]; then
  echo "Lỗi khởi động DHCP Server. Kiểm tra log tại $LOG_FILE." | tee -a $LOG_FILE
  exit 1
fi
echo "DHCP Server đã được cấu hình." >> $LOG_FILE

# Cài đặt và cấu hình DNS (Bind9)
echo "==== Cài đặt DNS (Bind9) ===="
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

# Đặt quyền cho các file cấu hình Bind9
chmod 644 /etc/bind/named.conf.local
chmod 644 /etc/bind/db.$DOMAIN
chmod 644 /etc/bind/named.conf.options

# Kiểm tra cấu hình DNS
named-checkconf >> $LOG_FILE 2>&1
named-checkzone "$DOMAIN" /etc/bind/db.$DOMAIN >> $LOG_FILE 2>&1
if [ $? -ne 0 ]; then
  echo "Lỗi cấu hình DNS. Kiểm tra log tại $LOG_FILE." | tee -a $LOG_FILE
  exit 1
fi

systemctl restart bind9 >> $LOG_FILE 2>&1
systemctl enable bind9 >> $LOG_FILE 2>&1
# Kiểm tra trạng thái Bind9
systemctl status bind9 >> $LOG_FILE 2>&1
if [ $? -ne 0 ]; then
  echo "Lỗi khởi động DNS Server. Kiểm tra log tại $LOG_FILE." | tee -a $LOG_FILE
  exit 1
fi
echo "DNS Server đã được cấu hình." >> $LOG_FILE

# Cài đặt và cấu hình Samba
echo "==== Cài đặt Samba ===="
apt install samba -y >> $LOG_FILE 2>&1

# Tạo các nhóm chia sẻ
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
  echo -e "123456\n123456" | smbpasswd -a $user >> $LOG_FILE 2>&1
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

systemctl restart smbd >> $LOG_FILE 2>&1
systemctl enable smbd >> $LOG_FILE 2>&1
# Kiểm tra trạng thái Samba
systemctl status smbd >> $LOG_FILE 2>&1
if [ $? -ne 0 ]; then
  echo "Lỗi khởi động Samba. Kiểm tra log tại $LOG_FILE." | tee -a $LOG_FILE
  exit 1
fi
echo "Samba đã được cấu hình." >> $LOG_FILE

# Cấu hình định tuyến giữa hai mạng
echo "==== Cấu hình định tuyến giữa hai mạng ===="
# Bật IP forwarding
sysctl -w net.ipv4.ip_forward=1 >> $LOG_FILE 2>&1
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
# Cấu hình tường lửa để cho phép định tuyến
ufw allow in on $INTERFACE_VANPHONG to any >> $LOG_FILE 2>&1
ufw allow in on $INTERFACE_BAOVE to any >> $LOG_FILE 2>&1
ufw allow out on $INTERFACE_VANPHONG to any >> $LOG_FILE 2>&1
ufw allow out on $INTERFACE_BAOVE to any >> $LOG_FILE 2>&1
echo "Đã cấu hình định tuyến giữa hai mạng." >> $LOG_FILE

# Cấu hình tường lửa (UFW)
echo "==== Cấu hình tường lửa (UFW) ===="
ufw default deny incoming >> $LOG_FILE 2>&1
ufw default allow outgoing >> $LOG_FILE 2>&1
ufw allow from 192.168.10.0/24 >> $LOG_FILE 2>&1
ufw allow from 192.168.20.0/24 >> $LOG_FILE 2>&1
ufw allow 67/udp >> $LOG_FILE 2>&1
ufw allow 53/udp >> $LOG_FILE 2>&1
ufw allow 53/tcp >> $LOG_FILE 2>&1
ufw allow 'Samba' >> $LOG_FILE 2>&1
ufw --force enable >> $LOG_FILE 2>&1
echo "Tường lửa đã được cấu hình." >> $LOG_FILE

# Thông báo hoàn tất
echo "==== CẤU HÌNH HOÀN TẤT ====" | tee -a $LOG_FILE
echo "IP văn phòng: $IP_VANPHONG" | tee -a $LOG_FILE
echo "IP bảo vệ: $IP_BAOVE" | tee -a $LOG_FILE
echo "Tên miền nội bộ: $DOMAIN" | tee -a $LOG_FILE
echo "Thư mục chia sẻ:" | tee -a $LOG_FILE
echo " - Văn phòng: /srv/share/vanphong" | tee -a $LOG_FILE
echo " - Bảo vệ: /srv/share/baove" | tee -a $LOG_FILE
echo " - Nhân sự: /srv/share/nhansu" | tee -a $LOG_FILE
echo " - Kế toán: /srv/share/ketoan" | tee -a $LOG_FILE
echo "Người dùng mặc định: LinhKeToan, TaiNhanSu, ThienBaoVe, Nhanbaove, Nhannhansu, BaoKeToan (mật khẩu: 123456)" | tee -a $LOG_FILE
echo "Kiểm tra chi tiết tại $LOG_FILE" | tee -a $LOG_FILE