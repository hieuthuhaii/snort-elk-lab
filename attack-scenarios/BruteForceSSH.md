# 🔐 Kịch bản: Phát hiện tấn công Brute Force SSH với Snort + ELK

## 🎯 Mục tiêu
Mô phỏng tấn công brute force dịch vụ SSH từ một máy Client, phát hiện bằng Snort, ghi log và hiển thị trên ELK Stack.

## 🖥️ Mô hình

- **Client (tấn công)**: 192.168.92.140
- **Server (Snort + ELK + SSH)**: 192.168.92.193

## 🔧 Bước 1: Viết rule Snort phát hiện brute force SSH

Tạo hoặc thêm vào `/etc/snort/rules/local.rules`:

alert tcp any any -> any 22 (msg:"Brute Force SSH Detected"; flow:to_server,established; detection_filter:track by_src, count 5, seconds 60; sid:1000002; rev:1;)r

Giải thích:
- `flow: to_server, established`: xác định luồng SSH hợp lệ
- `detection_filter`: nếu 5 lần kết nối trong 60s từ cùng IP → cảnh báo

## 🚀 Bước 2: Thực hiện tấn công brute force từ máy Client

Cài công cụ:

```bash
sudo apt install hydra -y
Tấn công SSH:


hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.92.193
👁️ Bước 3: Quan sát log Snort

sudo tail -f /var/log/snort/alert
Kết quả mẫu:


[**] [1:1000002:1] Brute Force SSH Detected [**]
📊 Bước 4: Hiển thị trên Kibana
Truy cập Kibana → Discover → Chọn index snort-logs*

Tìm theo message: "Brute Force SSH Detected"

✅ Kết quả mong đợi
Snort phát hiện IP brute-force và ghi log

Filebeat gửi log → Logstash → Elasticsearch

Kibana hiển thị cảnh báo trực quan
