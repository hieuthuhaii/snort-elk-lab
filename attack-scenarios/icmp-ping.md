# 🧪 Kịch bản 1: Phát hiện ICMP (Ping) bằng Snort và hiển thị trên ELK Stack

## 1. Mô hình mạng

- **Máy Client**: 192.168.92.140
- **Máy Server (cài Snort + ELK + Filebeat)**: 192.168.92.193

## 2. Cấu hình Snort để phát hiện ICMP

### ✅ Bước 1: Kiểm tra cấu hình Snort

```bash
sudo snort -i ens33 -c /etc/snort/snort.conf -T
Lệnh kiểm tra file cấu hình Snort (-T) để đảm bảo không có lỗi cú pháp.

✅ Bước 2: Mở file cấu hình chính

sudo nano /etc/snort/snort.conf
Bỏ dấu # dòng include $RULE_PATH/icmp.rules nếu bị comment

Đảm bảo Snort có thể nạp rule ICMP

✅ Bước 3: Tạo rule ICMP trong local.rules

alert icmp any any -> any any (msg:"PING Detected"; sid:1000001; rev:1;)
✅ Bước 4: Khởi động Snort ở chế độ giám sát

sudo snort -i ens33 -c /etc/snort/snort.conf
3. Gửi ping từ Client
Trên máy Client, chạy lệnh:


ping 192.168.92.193
Gói ICMP này sẽ bị Snort phát hiện và ghi log.

4. Kiểm tra log cảnh báo Snort
Trên máy Server, chạy:


sudo tail -f /var/log/snort/alert
Bạn sẽ thấy log có dạng:


[**] [1:1000001:1] PING Detected [**]
5. Hiển thị log trong Kibana
Truy cập Kibana: http://localhost:5601

Vào mục Discover

Tìm trong index: snort-logs*

Xem log ICMP với nội dung như:

message: [1:1000001:1] PING Detected

host.ip: IP máy server

log.file.path: /var/log/snort/alert

6. Diễn giải trường dữ liệu trong Kibana
Trường	Ý nghĩa
@timestamp	Thời điểm log được ghi
message	Nội dung cảnh báo từ Snort
agent.hostname	Tên máy gửi log (máy chạy Filebeat)
log.file.path	Đường dẫn file log mà Filebeat theo dõi (/var/log/snort/alert)
host.ip	IP của máy giám sát
input.type	Loại dữ liệu đầu vào (log)

7. Thống kê Snort (tuỳ chọn)
Chạy lệnh sau để xem thống kê:


sudo snort -i ens33 -c /etc/snort/snort.conf
Bạn sẽ thấy:

ICMP: số gói tin ping

Alerts: số lượng cảnh báo tạo ra

Logged: số cảnh báo được ghi vào file

Passed: số gói được bỏ qua (nếu có rule pass)

✅ Kết quả mong đợi
Snort phát hiện được ICMP từ client → log vào file

Filebeat gửi log đến Logstash → lưu vào Elasticsearch

Kibana hiển thị log ICMP trong Discover
