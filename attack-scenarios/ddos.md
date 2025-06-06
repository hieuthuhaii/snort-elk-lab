# 🌐 Kịch bản: Phát hiện tấn công DoS/DDoS với Snort + ELK

## 🎯 Mục tiêu
Giả lập tấn công DoS từ Client sang Server, sử dụng công cụ `hping3`. Snort phát hiện và log gửi đến ELK Stack.

## 🖥️ Mô hình

- **Client (tấn công)**: 192.168.92.140
- **Server (Snort + ELK)**: 192.168.92.193

## 🔧 Bước 1: Tạo rule Snort phát hiện DoS

Thêm vào `/etc/snort/rules/local.rules`:

alert tcp any any -> any 80 (msg:"Possible DoS attack detected"; flow:to_server; threshold:type both, track by_src, count 20, seconds 5; sid:1000003; rev:1;)less


## 🚀 Bước 2: Thực hiện tấn công DoS

Cài `hping3`:

```bash
sudo apt install hping3 -y
Chạy lệnh tấn công từ Client:


sudo hping3 -S --flood -p 80 192.168.92.193
Giải thích:

-S: gửi gói SYN

--flood: gửi liên tục không dừng

-p 80: nhắm cổng 80

👁️ Bước 3: Quan sát log Snort

sudo tail -f /var/log/snort/alert
Kết quả mong đợi:

[**] [1:1000003:1] Possible DoS attack detected [**]
📊 Bước 4: Kiểm tra Kibana
Truy cập Kibana tại http://localhost:5601

Discover → tìm message: "Possible DoS attack detected"

✅ Kết quả mong đợi
Snort phát hiện gói tin bất thường với số lượng cao

Log được gửi đến ELK Stack

Kibana hiển thị cảnh báo với đầy đủ thông tin IP, thời gian, message
