#!/usr/bin/env python3
import re
import time
import subprocess
import threading
from collections import defaultdict

# Đường dẫn file log của Snort
LOG_FILE = '/var/log/snort/alert'

# Biểu thức chính quy để tìm địa chỉ IP trong log
IP_REGEX = re.compile(r'(\d+\.\d+\.\d+\.\d+)')

# Số lần cảnh báo trước khi chặn IP
THRESHOLD = 3

# Thời gian kiểm tra số lần cảnh báo (tính bằng giây)
TIME_WINDOW = 300  # 5 phút

# Thời gian chặn IP (tính bằng giây)
BAN_DURATION = 600  # 10 phút

# Dictionary lưu danh sách timestamp của từng IP bị cảnh báo
ip_alerts = defaultdict(list)

# Danh sách IP đang bị chặn
blocked_ips = set()


def unblock_ip(ip):
    """Hàm bỏ chặn một IP bằng lệnh iptables."""
    try:
        subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Đã bỏ chặn IP: {ip}")
    except subprocess.CalledProcessError as e:
        print(f"Lỗi khi bỏ chặn IP {ip}: {e}")
    finally:
        blocked_ips.discard(ip)


def schedule_unblock(ip, duration):
    """Hàm chờ trong khoảng thời gian BAN_DURATION rồi bỏ chặn IP."""
    time.sleep(duration)
    unblock_ip(ip)


def block_ip(ip):
    """Hàm chặn một IP bằng iptables nếu chưa bị chặn."""
    if ip in blocked_ips:
        return

    try:
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Đã chặn IP: {ip} trong {BAN_DURATION} giây")
        blocked_ips.add(ip)
        threading.Thread(target=schedule_unblock, args=(ip, BAN_DURATION), daemon=True).start()
    except subprocess.CalledProcessError as e:
        print(f"Lỗi khi chặn IP {ip}: {e}")


def monitor_log():
    """Hàm giám sát file log Snort để phát hiện và chặn IP đáng ngờ."""
    try:
        with open(LOG_FILE, 'r') as f:
            f.seek(0, 2)  # Đọc từ cuối file
            while True:
                line = f.readline()
                if not line:
                    time.sleep(1)
                    continue

                match = IP_REGEX.search(line)
                if match:
                    ip = match.group(1)
                    if ip in blocked_ips:
                        continue

                    now = time.time()
                    ip_alerts[ip].append(now)
                    # Chỉ giữ lại các cảnh báo trong khoảng TIME_WINDOW
                    ip_alerts[ip] = [t for t in ip_alerts[ip] if now - t < TIME_WINDOW]

                    if len(ip_alerts[ip]) >= THRESHOLD:
                        block_ip(ip)
                        del ip_alerts[ip]
    except FileNotFoundError:
        print(f"Không tìm thấy file log: {LOG_FILE}.")


if __name__ == '__main__':
    print("Bắt đầu giám sát log Snort tại", LOG_FILE)
    monitor_log()
