# 🛡️ Lab Giám Sát An Toàn Thông Tin với Snort và ELK Stack (All-in-One)

## 🧩 Mô tả

Dự án này triển khai một hệ thống giám sát an toàn thông tin trên **một máy Ubuntu duy nhất**, kết hợp giữa:
- **Snort**: Hệ thống phát hiện xâm nhập (IDS)
- **ELK Stack**: Bao gồm Elasticsearch, Logstash, Kibana để lưu trữ, xử lý và hiển thị log
- **Filebeat**: Thu thập log từ Snort và gửi đến Logstash

Hệ thống có thể phát hiện và ghi nhận các hành vi tấn công như:
- Ping ICMP
- Port Scanning
- Brute Force SSH

## 🖼️ Kiến trúc tổng thể

![System Architecture](architecture.png)

## 📁 Nội dung repo
snort-elk-lab/
├── README.md
├── INSTALL.md
├── config/
│ ├── snort/
│ │ ├── snort.conf
│ │ └── rules/local.rules
│ ├── filebeat.yml
│ ├── logstash.conf
│ ├── elasticsearch.yml
│ └── kibana.yml
├── attack-scenarios/
│ ├── pingicmp.md
│ ├── BruteforceSSH.md
│ └── portscan.md
├── scripts/
│ └── block_ip.py
└── dashboards/
## ▶️ Bắt đầu

1. Xem hướng dẫn cài đặt tại [`INSTALL.md`](INSTALL.md)
2. Chạy các kịch bản mô phỏng trong thư mục `attack-scenarios/`
3. Quan sát log trên giao diện Kibana
4. Tùy chọn: tích hợp script `block_ip.py` để tự động chặn IP

## ✅ Yêu cầu hệ thống

- Ubuntu Server/Desktop (khuyến nghị 20.04 hoặc 22.04)
- RAM tối thiểu 4GB
- Quyền `sudo`
