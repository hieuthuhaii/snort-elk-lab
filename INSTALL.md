🛠️ HƯỚNG DẪN CÀI ĐẶT VÀ CẤU HÌNH SNORT + ELK STACK (TRÊN CÙNG MÁY)
________________________________________
🧱 0. Chuẩn bị ban đầu

sudo apt update && sudo apt upgrade -y
sudo hostnamectl set-hostname elkserver
sudo timedatectl set-timezone Asia/Ho_Chi_Minh
________________________________________
🔹 1. Cài đặt Java JDK 8 (Yêu cầu cho Elasticsearch)

sudo apt install -y openjdk-8-jdk
________________________________________
🔹 2. Cài đặt ELK Stack (Elasticsearch, Logstash, Kibana)
2.1 Thêm kho Elastic và cài đặt

wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt-get update
2.2 Cài Elasticsearch

sudo apt-get install -y elasticsearch
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch
2.3 Cài Kibana

sudo apt-get install -y kibana
sudo nano /etc/kibana/kibana.yml
# Thêm dòng:
server.host: "0.0.0.0"
sudo systemctl enable kibana
sudo systemctl start kibana
2.4 Cài Logstash

sudo apt-get install -y logstash
sudo systemctl enable logstash
________________________________________
🔹 3. Cài đặt và cấu hình Snort (phiên bản 2.9.20)
3.1 Cài các gói phụ thuộc

sudo apt install -y build-essential libpcap-dev libpcre3-dev libdumbnet-dev bison flex zlib1g-dev liblzma-dev openssl libssl-dev libntirpc-dev
3.2 Cài đặt DAQ

mkdir ~/snort_src && cd ~/snort_src
wget https://www.snort.org/downloads/snort/daq-2.0.7.tar.gz
tar -xvzf daq-2.0.7.tar.gz && cd daq-2.0.7
./configure && make && sudo make install
3.3 Cài đặt Snort

cd ~/snort_src
wget https://www.snort.org/downloads/snort/snort-2.9.20.tar.gz
tar -zxf snort-2.9.20.tar.gz && cd snort-2.9.20
./configure --enable-sourcefire --disable-open-appid
make CFLAGS=-I/usr/include/ntirpc
sudo make install
sudo ldconfig
sudo ln -s /usr/local/bin/snort /usr/sbin/snort
3.4 Tạo cấu trúc thư mục Snort

sudo mkdir -p /etc/snort/rules /etc/snort/preproc_rules /etc/snort/so_rules /etc/snort/rules/iplists /var/log/snort /var/log/snort/archived_logs /usr/local/lib/snort_dynamicrules
sudo touch /etc/snort/rules/local.rules /etc/snort/rules/iplists/black_list.rules /etc/snort/rules/iplists/white_list.rules /etc/snort/sid-msg.map
3.5 Copy cấu hình mẫu

cd ~/snort_src/snort-2.9.20/etc
sudo cp *.conf *.map *.dtd /etc/snort/
________________________________________
🔹 4. Cấu hình Snort để phát hiện tấn công
4.1 Sửa file cấu hình Snort

sudo nano /etc/snort/snort.conf
•	Tìm dòng ipvar HOME_NET và sửa:

ipvar HOME_NET 192.168.1.0/24
•	Đảm bảo dòng sau tồn tại:
Bỏ dấu #, các dòng còn lại thêm #
include $RULE_PATH/local.rules
4.2 Thêm rule đơn giản để phát hiện ICMP (ping)

sudo nano /etc/snort/rules/local.rules
Thêm:
snort

alert icmp any any -> any any (msg:"ICMP Packet Detected"; sid:1000001; rev:1;)
4.3 Chạy Snort và ghi log

sudo snort -i eth0 -A fast -c /etc/snort/snort.conf -l /var/log/snort
⚠️ Thay eth0 bằng interface mạng thật (xem với ip a)
________________________________________
🔹 5. Cài đặt và cấu hình Filebeat để gửi log Snort
5.1 Cài đặt Filebeat

sudo apt-get install -y filebeat
5.2 Sửa cấu hình Filebeat

sudo nano /etc/filebeat/filebeat.yml
Thay nội dung như sau:
yaml
Sao chépChỉnh sửa
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/snort/alert
  fields:
    log_type: snort

output.logstash:
  hosts: ["localhost:5044"]
5.3 Bật Filebeat

sudo systemctl enable filebeat
sudo systemctl start filebeat
________________________________________
🔹 6. Cấu hình Logstash để xử lý log Snort
6.1 Tạo file cấu hình:

sudo nano /etc/logstash/conf.d/02-snort.conf
6.2 Nội dung file:

input {
  beats {
    port => 5044
  }
}

filter {
  if [fields][log_type] == "snort" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:host} snort\[%{NUMBER:pid}\]: \[%{DATA:classification}\] %{GREEDYDATA:snort_message}" }
    }
    date {
      match => [ "timestamp", "MMM dd HH:mm:ss", "MMM  d HH:mm:ss" ]
      target => "@timestamp"
    }
  }
}

output {
  if [fields][log_type] == "snort" {
    elasticsearch {
      hosts => ["http://localhost:9200"]
      index => "snort-logs-%{+YYYY.MM.dd}"
    }
  }
}
6.3 Khởi động lại Logstash

sudo systemctl restart logstash
________________________________________
🔹 7. Cấu hình Kibana để xem log Snort
7.1 Truy cập Kibana:

http://localhost:5601
7.2 Tạo Index Pattern
•	Vào: Stack Management > Index Patterns
•	Nhập: snort-logs-*
•	Chọn @timestamp làm field thời gian
________________________________________
🔹 8. Kiểm tra hoạt động hệ thống
8.1 Tạo sự kiện (ping để kích hoạt rule)

ping 127.0.0.1 -c 4
8.2 Kiểm tra file log Snort:

cat /var/log/snort/alert
8.3 Kiểm tra Kibana (Discover tab)
•	Mở Discover
•	Chọn snort-logs-*
•	Kiểm tra log được gửi lên
________________________________________
🔐 Mở firewall nếu cần (nếu dùng UFW):

sudo ufw allow 5044
________________________________________
✅ TỔNG KẾT DÒNG CHẢY LOG

[Snort] --> /var/log/snort/alert
   ↓
[Filebeat] --> [Logstash] --> [Elasticsearch] --> [Kibana]
________________________________________
📦 BONUS: Tạo service để chạy Snort tự động (nếu cần)
Muốn không phải chạy Snort thủ công, bạn có thể tạo file systemd:

sudo nano /etc/systemd/system/snort.service
ini

[Unit]
Description=Snort IDS Daemon
After=network.target

[Service]
ExecStart=/usr/sbin/snort -i eth0 -A fast -c /etc/snort/snort.conf -l /var/log/snort
Restart=always

[Install]
WantedBy=multi-user.target

sudo systemctl daemon-reexec
sudo systemctl enable snort
sudo systemctl start snort


