#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UDP Client - 模拟TCP可靠传输
功能：
1. 命令行指定serverIP和serverPort
2. 模拟TCP连接建立（三次握手：SYN → SYN-ACK → ACK）
3. 发送窗口400字节（GBN协议）
4. 超时重传 + 自适应超时
5. 计算RTT和服务器时间
6. 统计信息（pandas）
7. 记录运行日志
"""

import socket
import struct
import time
import sys
import os
import random
from datetime import datetime
import pandas as pd

# ==================== 配置参数 ====================
TIMEOUT_MS = 300            # 初始超时时间（毫秒）
WINDOW_SIZE = 400           # 发送窗口大小（字节）
MIN_PKT_SIZE = 40           # 最小数据包大小
MAX_PKT_SIZE = 80           # 最大数据包大小
TOTAL_PACKETS = 30          # 需要发送的数据包总数
STUDENT_ID_SUFFIX = "1310"  # 学号后4位（请修改为你的学号后4位）

# ==================== 协议首部定义 ====================
"""
自定义应用层协议首部（10字节固定长度）：
+--------+--------+--------+--------+--------+--------+
|  类型   |  标志   |   序列号  |   确认号  |   数据长度  | StudentID |
| 1字节  | 1字节  |  2字节   |  2字节   |   2字节    |  2字节   |
+--------+--------+--------+--------+--------+--------+
|                      数据（可变长度）                      |
+----------------------------------------------------------+
"""

HEADER_FORMAT = '!BBHHHH'   # 网络字节序
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # = 10 字节

# 报文类型常量
TYPE_SYN = 0x01
TYPE_SYN_ACK = 0x02
TYPE_DATA = 0x03
TYPE_ACK = 0x04
TYPE_FIN = 0x05
TYPE_FIN_ACK = 0x06

# 标志位常量
FLAG_RETRANS = 0x01
FLAG_CUMULATIVE = 0x02

LOG_FILE = 'run_log.txt'


class PacketInfo:
    """记录每个数据包的信息"""
    def __init__(self, seq_num, byte_start, byte_end, payload, is_retrans=False):
        self.seq_num = seq_num
        self.byte_start = byte_start
        self.byte_end = byte_end
        self.payload = payload          # 预生成的payload（字节串），重传时复用
        self.is_retrans = is_retrans
        self.send_time = None
        self.recv_time = None
        self.rtt = None
        self.acked = False
        self.timeout_count = 0


def log_event(event_type, details):
    """记录日志事件"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    log_line = f"[{timestamp}] [{event_type}] {details}\n"
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(log_line)
    print(log_line.strip())


def create_header(pkt_type, flags, seq_num, ack_num, data_len, student_id):
    """创建协议首部"""
    return struct.pack(HEADER_FORMAT, pkt_type, flags, seq_num, ack_num, data_len, student_id)


def parse_header(data):
    """解析协议首部"""
    if len(data) < HEADER_SIZE:
        return None
    return struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])


def compute_student_id_field(student_suffix):
    """计算StudentID字段：学号后4位 XOR 0x5A3C"""
    suffix_int = int(student_suffix)
    return suffix_int ^ 0x5A3C


def generate_payload(size):
    """生成指定大小的随机数据（可打印ASCII字符）"""
    chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    return ''.join(random.choice(chars) for _ in range(size)).encode('utf-8')


def calculate_adaptive_timeout(rtt_list):
    """
    根据RTT历史计算自适应超时时间
    使用简化公式：avg_rtt * 2，最小100ms，最大5000ms
    注意：rtt_list 中的值单位是毫秒
    """
    if not rtt_list:
        return TIMEOUT_MS / 1000.0  # 默认300ms → 0.3秒
    avg_rtt = sum(rtt_list) / len(rtt_list)  # 毫秒
    timeout_ms = max(avg_rtt * 2, 100.0)      # 最小100ms
    timeout_ms = min(timeout_ms, 5000.0)       # 最大5000ms（防止膨胀过大）
    return timeout_ms / 1000.0                  # 转换为秒


def main():
    if len(sys.argv) != 3:
        print("用法: python udpclient.py <serverIP> <serverPort>")
        print("示例: python udpclient.py 127.0.0.1 12000")
        sys.exit(1)

    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    server_addr = (server_ip, server_port)

    # 计算StudentID字段
    student_id_field = compute_student_id_field(STUDENT_ID_SUFFIX)

    print("=" * 60)
    print("         UDP Client - 模拟TCP可靠传输")
    print("=" * 60)
    print(f"服务器地址: {server_ip}:{server_port}")
    print(f"学号后4位: {STUDENT_ID_SUFFIX}")
    print(f"StudentID字段值: {student_id_field:#06x} (XOR 0x5A3C)")
    print(f"初始超时时间: {TIMEOUT_MS}ms")
    print(f"发送窗口: {WINDOW_SIZE}字节")
    print(f"目标数据包数: {TOTAL_PACKETS}")
    print(f"日志文件: {LOG_FILE}")
    print("=" * 60 + "\n")

    log_event("CLIENT", f"Client启动，目标服务器:{server_addr}")

    # 创建UDP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(TIMEOUT_MS / 1000.0)

    # ==================== 阶段1: 连接建立（三次握手） ====================
    print("【阶段1】连接建立（三次握手）...")
    log_event("CONN", "开始连接建立过程（SYN）")

    # 第一步：发送SYN
    syn_header = create_header(TYPE_SYN, 0, 0, 0, 0, student_id_field)
    client_socket.sendto(syn_header, server_addr)
    log_event("SEND", f"发送SYN to {server_addr}")

    # 第二步：等待SYN-ACK
    connected = False
    retry_count = 0
    max_retries = 5

    while not connected and retry_count < max_retries:
        try:
            data, addr = client_socket.recvfrom(2048)
            header = parse_header(data)

            if header and header[0] == TYPE_SYN_ACK:
                log_event("RECV", f"收到SYN-ACK from {addr}")
                print("收到SYN-ACK，发送握手ACK确认...")
                connected = True
            else:
                log_event("WARN", f"握手阶段收到非预期响应: type={header[0] if header else 'None'}")

        except socket.timeout:
            retry_count += 1
            log_event("TIMEOUT", f"等待SYN-ACK超时，重试 {retry_count}/{max_retries}")
            client_socket.sendto(syn_header, server_addr)
            log_event("SEND", f"重发SYN to {server_addr}")

    if not connected:
        print("连接建立失败！")
        log_event("ERROR", "连接建立失败，退出")
        sys.exit(1)

    # 第三步：发送握手ACK，完成三次握手
    ack_handshake = create_header(TYPE_ACK, 0, 0, 0, 0, student_id_field)
    client_socket.sendto(ack_handshake, server_addr)
    log_event("SEND", f"发送握手ACK to {server_addr}，三次握手完成")
    print("连接建立成功！（三次握手完成）\n")

    # ==================== 阶段2: 数据传输 ====================
    print("【阶段2】数据传输（GBN协议）...\n")
    log_event("DATA", "进入数据传输阶段")

    # ---- 预生成所有数据包的payload，确保字节范围一致 ----
    packets = []
    current_byte = 0

    for i in range(1, TOTAL_PACKETS + 1):
        # 随机生成40-80字节的数据（预生成payload，发送和重传时复用）
        data_size = random.randint(MIN_PKT_SIZE, MAX_PKT_SIZE)
        payload = generate_payload(data_size)
        byte_start = current_byte
        byte_end = current_byte + data_size - 1

        pkt = PacketInfo(i, byte_start, byte_end, payload)
        packets.append(pkt)
        current_byte += data_size

    print(f"准备发送 {TOTAL_PACKETS} 个数据包，总数据量 {current_byte} 字节\n")

    # GBN发送窗口管理
    base = 1                # 窗口起始序列号
    next_seq = 1            # 下一个待发送序列号

    # RTT统计
    rtt_list = []
    total_sent = 0          # 总发送次数（含重传）
    retrans_count = 0       # 重传次数

    # 超时时间管理
    current_timeout = TIMEOUT_MS / 1000.0
    timer_start = None

    all_acked = False

    while not all_acked:
        # 发送窗口内的数据包
        while next_seq <= TOTAL_PACKETS and (next_seq - base) * MAX_PKT_SIZE < WINDOW_SIZE:
            pkt = packets[next_seq - 1]

            # 使用预生成的payload（重传时复用同一份数据）
            payload = pkt.payload
            actual_len = len(payload)

            flags = FLAG_RETRANS if pkt.is_retrans else 0
            data_header = create_header(TYPE_DATA, flags, pkt.seq_num, 0,
                                        actual_len, student_id_field)
            packet_data = data_header + payload

            client_socket.sendto(packet_data, server_addr)
            pkt.send_time = time.time()
            total_sent += 1

            if pkt.is_retrans:
                retrans_count += 1
                print(f"  重传第 {pkt.seq_num} 个（第 {pkt.byte_start}~{pkt.byte_end} 字节）数据包")
                log_event("RETRANS", f"重传 seq={pkt.seq_num}, 字节范围:{pkt.byte_start}~{pkt.byte_end}")
            else:
                print(f"  第 {pkt.seq_num} 个（第 {pkt.byte_start}~{pkt.byte_end} 字节）client 端已经发送")
                log_event("SEND", f"发送DATA seq={pkt.seq_num}, 字节范围:{pkt.byte_start}~{pkt.byte_end}, len={actual_len}")

            next_seq += 1

            # 启动定时器（如果还没启动）
            if timer_start is None:
                timer_start = time.time()

        # 等待ACK或超时
        try:
            client_socket.settimeout(current_timeout)
            data, addr = client_socket.recvfrom(2048)
            header = parse_header(data)

            if header and header[0] == TYPE_ACK:
                ack_num = header[3]        # 确认号
                flags = header[1]
                data_len = header[4]       # ACK负载长度（服务器时间字符串长度）
                recv_time = time.time()

                # 解析服务器时间（从ACK负载中提取）
                server_time_str = ""
                if data_len > 0:
                    try:
                        payload_data = data[HEADER_SIZE:HEADER_SIZE + data_len]
                        server_time_str = payload_data.decode('utf-8')
                    except:
                        server_time_str = "未知"

                log_event("RECV", f"收到ACK ack={ack_num}, flags={flags:#04x}, 服务器时间={server_time_str}")

                # 处理累积确认
                if ack_num >= base:
                    # 计算被确认包的RTT
                    for seq in range(base, ack_num + 1):
                        if seq <= TOTAL_PACKETS and not packets[seq - 1].acked:
                            pkt = packets[seq - 1]
                            pkt.acked = True
                            pkt.recv_time = recv_time
                            if pkt.send_time:
                                rtt = (recv_time - pkt.send_time) * 1000  # ms
                                pkt.rtt = rtt
                                rtt_list.append(rtt)

                    # 打印每个新确认包的确认信息
                    for seq in range(base, ack_num + 1):
                        if seq <= TOTAL_PACKETS and packets[seq - 1].acked:
                            pkt = packets[seq - 1]
                            if pkt.rtt is not None:
                                print(f"  第 {pkt.seq_num} 个（第 {pkt.byte_start}~{pkt.byte_end} 字节）"
                                      f"server 端已经收到，RTT 是 {pkt.rtt:.2f} ms，服务器时间 {server_time_str}")
                                log_event("ACKED", f"seq={pkt.seq_num} 已确认, RTT={pkt.rtt:.2f}ms")

                    # 更新窗口
                    base = ack_num + 1
                    timer_start = None   # 重置定时器

                    # 更新自适应超时时间
                    if rtt_list:
                        current_timeout = calculate_adaptive_timeout(rtt_list)
                        log_event("TIMER", f"更新超时时间为 {current_timeout*1000:.1f}ms")

                    # 检查是否全部确认
                    if base > TOTAL_PACKETS:
                        all_acked = True
                        log_event("INFO", "所有数据包已确认")

            elif header and header[0] == TYPE_SYN_ACK:
                # 忽略重复的SYN-ACK
                log_event("INFO", "收到重复SYN-ACK，忽略")

        except socket.timeout:
            # 超时：重传base到next_seq-1的所有包
            log_event("TIMEOUT", f"超时! base={base}, next_seq={next_seq}, 重传窗口内所有包")
            print(f"\n  *** 超时！重传从 seq={base} 开始的所有未确认包 ***")

            for seq in range(base, next_seq):
                if seq <= TOTAL_PACKETS:
                    packets[seq - 1].is_retrans = True
                    packets[seq - 1].timeout_count += 1

            next_seq = base   # 回退next_seq
            timer_start = None

    # ==================== 阶段3: 连接释放 ====================
    print("\n【阶段3】连接释放...")
    log_event("CONN", "开始连接释放过程（FIN）")

    fin_header = create_header(TYPE_FIN, 0, 0, 0, 0, student_id_field)
    client_socket.sendto(fin_header, server_addr)
    log_event("SEND", f"发送FIN to {server_addr}")

    try:
        client_socket.settimeout(5.0)
        data, addr = client_socket.recvfrom(2048)
        header = parse_header(data)
        if header and header[0] == TYPE_FIN_ACK:
            log_event("RECV", f"收到FIN-ACK from {addr}")
            print("连接释放成功！\n")
    except socket.timeout:
        log_event("TIMEOUT", "等待FIN-ACK超时")
        print("连接释放超时（可能服务器已关闭）\n")

    client_socket.close()

    # ==================== 阶段4: 统计汇总 ====================
    print("=" * 60)
    print("                    【汇总信息】")
    print("=" * 60)

    # 丢包率："30 ÷ 实际发送的 udp packet number" 计算
    loss_rate = (TOTAL_PACKETS / total_sent) * 100 if total_sent > 0 else 0
    print(f"● 丢包率: {loss_rate:.2f}%")
    print(f"  （按 {TOTAL_PACKETS} ÷ {total_sent} 计算）")
    log_event("STATS", f"丢包率:{loss_rate:.2f}%, 目标包数:{TOTAL_PACKETS}, 实际发送:{total_sent}")

    # RTT统计（使用pandas）
    if rtt_list:
        df = pd.DataFrame({'RTT(ms)': rtt_list})
        print(f"\n● RTT统计（使用pandas）：")
        print(f"  最大RTT: {df['RTT(ms)'].max():.2f} ms")
        print(f"  最小RTT: {df['RTT(ms)'].min():.2f} ms")
        print(f"  平均RTT: {df['RTT(ms)'].mean():.2f} ms")
        print(f"  RTT标准差: {df['RTT(ms)'].std():.2f} ms")
        log_event("STATS", f"RTT统计: max={df['RTT(ms)'].max():.2f}, min={df['RTT(ms)'].min():.2f}, "
                          f"mean={df['RTT(ms)'].mean():.2f}, std={df['RTT(ms)'].std():.2f}")
    else:
        print("\n● 无RTT数据（可能全部丢包）")

    print(f"\n● 重传次数: {retrans_count}")
    print(f"● 总发送次数: {total_sent}")
    print(f"● 日志文件: {os.path.abspath(LOG_FILE)}")
    print("=" * 60)

    log_event("CLIENT", "Client正常结束")


if __name__ == '__main__':
    main()
