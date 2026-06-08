#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UDP Server - 模拟TCP可靠传输
功能：
1. 接收连接请求，验证StudentID
2. 随机丢包模拟不可靠传输
3. 累积确认（GBN风格）
4. 在ACK中携带服务器系统时间
5. 记录运行日志
"""

import socket
import struct
import time
import random
import sys
import os
from datetime import datetime

# ==================== 配置参数 ====================
LOSS_RATE = 0.3             # 丢包率 30%（可调整）
BUFFER_SIZE = 2048          # 接收缓冲区大小

# ==================== 协议首部定义 ====================
"""
自定义应用层协议首部（10字节固定长度）：
+--------+--------+--------+--------+--------+--------+
|  类型   |  标志   |   序列号  |   确认号  |   数据长度  | StudentID |
| 1字节  | 1字节  |  2字节   |  2字节   |   2字节    |  2字节   |
+--------+--------+--------+--------+--------+--------+
|                      数据（可变长度）                      |
+----------------------------------------------------------+

类型字段：
  0x01 = 连接请求 (SYN)
  0x02 = 连接确认 (SYN-ACK)
  0x03 = 数据包   (DATA)
  0x04 = 确认包   (ACK)
  0x05 = 连接释放 (FIN)
  0x06 = 释放确认 (FIN-ACK)

标志字段：
  bit 0 = 是否为重传包
  bit 1 = 是否为累积确认
  bit 2-7 = 保留
"""

HEADER_FORMAT = '!BBHHHH'  # 网络字节序: 类型(1) 标志(1) 序列号(2) 确认号(2) 数据长度(2) StudentID(2)
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

# 全局日志文件（server端单独日志，避免与client端竞争写入）
LOG_FILE = 'run_log_server.txt'


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


def verify_student_id(received_id):
    """验证StudentID：接收到的值 XOR 0x5A3C 应在 0-9999范围内"""
    # 注意：这里接收到的值是客户端已经XOR 0x5A3C后的值
    # 所以服务器需要再次XOR 0x5A3C来还原原始学号后4位
    original = received_id ^ 0x5A3C
    return 0 <= original <= 9999, original


def get_server_time():
    """获取服务器系统时间 hh-mm-ss格式"""
    return datetime.now().strftime('%H-%M-%S')


def main():
    if len(sys.argv) != 2:
        print("用法: python udpserver.py <port>")
        print("示例: python udpserver.py 12000")
        sys.exit(1)

    server_port = int(sys.argv[1])

    # 创建UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('', server_port))

    print(f"===== UDP Server 启动 =====")
    print(f"监听端口: {server_port}")
    print(f"丢包率: {LOSS_RATE*100}%")
    print(f"日志文件: {LOG_FILE}")
    print("等待客户端连接...\n")

    log_event("SERVER", f"Server启动，端口:{server_port}, 丢包率:{LOSS_RATE*100}%")

    # 等待连接请求（SYN）
    connected = False
    client_addr = None
    expected_seq = 1  # 期望接收的序列号（GBN）
    client_student_id = None  # 保存客户端StudentID，用于后续回复

    while not connected:
        data, addr = server_socket.recvfrom(BUFFER_SIZE)
        header = parse_header(data)

        if header is None:
            continue

        pkt_type, flags, seq_num, ack_num, data_len, student_id = header

        if pkt_type == TYPE_SYN:
            log_event("RECV", f"收到SYN连接请求 from {addr}, StudentID字段:{student_id:#06x}")

            # 验证StudentID
            valid, original_id = verify_student_id(student_id)

            if not valid:
                log_event("ERROR", f"StudentID验证失败! 原始值:{original_id} 不在0-9999范围内")
                print(f"拒绝连接：StudentID {student_id:#06x} 验证失败（原始值:{original_id}）")
                continue

            log_event("INFO", f"StudentID验证通过，原始学号后4位:{original_id:04d}")
            client_student_id = student_id

            # 发送SYN-ACK
            syn_ack_header = create_header(TYPE_SYN_ACK, 0, 0, 0, 0, student_id)
            server_socket.sendto(syn_ack_header, addr)
            log_event("SEND", f"发送SYN-ACK to {addr}")

            # 等待客户端的三次握手ACK确认
            try:
                server_socket.settimeout(5.0)
                data3, addr3 = server_socket.recvfrom(BUFFER_SIZE)
                header3 = parse_header(data3)
                if header3 and header3[0] == TYPE_ACK and addr3 == addr:
                    log_event("RECV", f"收到握手ACK from {addr3}，三次握手完成")
                    client_addr = addr
                    connected = True
                    print(f"\n客户端 {addr} 连接建立成功！（三次握手完成）\n")
                    log_event("INFO", f"连接建立完成，开始数据传输阶段")
                else:
                    log_event("WARN", f"握手阶段收到非预期报文 type={header3[0] if header3 else 'None'}")
            except socket.timeout:
                log_event("TIMEOUT", "等待握手ACK超时，继续监听SYN")
                # 不设置connected，回到外层循环继续等待SYN

    # 数据传输阶段
    received_packets = set()  # 已接收的序列号集合
    total_data_packets = 0

    print("===== 进入数据传输阶段 =====\n")

    while True:
        try:
            server_socket.settimeout(10.0)  # 10秒超时等待
            data, addr = server_socket.recvfrom(BUFFER_SIZE)

            if addr != client_addr:
                log_event("WARN", f"收到未知来源数据: {addr}")
                continue

            header = parse_header(data)
            if header is None:
                continue

            pkt_type, flags, seq_num, ack_num, data_len, student_id = header
            payload = data[HEADER_SIZE:HEADER_SIZE + data_len]

            if pkt_type == TYPE_DATA:
                total_data_packets += 1
                recv_time = time.time()

                log_event("RECV", f"收到DATA包 seq={seq_num}, len={data_len}, flags={flags:#04x}")

                # 模拟丢包：随机决定是否"丢弃"（不响应）
                if random.random() < LOSS_RATE:
                    log_event("DROP", f"模拟丢包! seq={seq_num} (随机丢弃，假装没收到)")
                    print(f"  [丢包] 丢弃 seq={seq_num} 的数据包")
                    continue

                # 处理数据包（GBN累积确认）
                if seq_num == expected_seq:
                    # 收到期望的序列号，更新期望序列号
                    expected_seq += 1
                    received_packets.add(seq_num)
                    log_event("INFO", f"seq={seq_num} 符合预期，更新expected_seq={expected_seq}")

                    # 发送累积确认（确认到expected_seq-1），附带服务器时间
                    server_time = get_server_time()
                    ack_header = create_header(TYPE_ACK, FLAG_CUMULATIVE, 0,
                                               expected_seq - 1, len(server_time),
                                               client_student_id)
                    ack_packet = ack_header + server_time.encode('utf-8')
                    server_socket.sendto(ack_packet, addr)
                    log_event("SEND", f"发送累积ACK ack={expected_seq-1}, 服务器时间={server_time} to {addr}")
                    print(f"  [确认] 发送累积ACK ack={expected_seq-1}, 服务器时间={server_time}")

                elif seq_num < expected_seq:
                    # 收到重复包（已确认过的），再次发送ACK（附带服务器时间）
                    log_event("INFO", f"seq={seq_num} 已确认过（重复包），重发ACK")
                    server_time = get_server_time()
                    ack_header = create_header(TYPE_ACK, FLAG_CUMULATIVE, 0,
                                               expected_seq - 1, len(server_time),
                                               client_student_id)
                    ack_packet = ack_header + server_time.encode('utf-8')
                    server_socket.sendto(ack_packet, addr)
                    log_event("SEND", f"发送累积ACK ack={expected_seq-1}, 服务器时间={server_time} to {addr} (重复包响应)")

                else:
                    # 收到乱序包（seq_num > expected_seq），GBN中丢弃
                    log_event("DROP", f"seq={seq_num} 乱序（expected={expected_seq}），GBN丢弃")
                    print(f"  [乱序丢弃] seq={seq_num} > expected={expected_seq}")
                    # 不发送ACK，让客户端超时重传

            elif pkt_type == TYPE_ACK:
                # 数据传输阶段不应收到ACK（握手阶段已过），忽略
                log_event("INFO", f"收到数据传输阶段的ACK seq={seq_num}，忽略")

            elif pkt_type == TYPE_FIN:
                log_event("RECV", f"收到FIN连接释放请求 from {addr}")
                # 发送FIN-ACK
                fin_ack_header = create_header(TYPE_FIN_ACK, 0, 0, 0, 0, client_student_id)
                server_socket.sendto(fin_ack_header, addr)
                log_event("SEND", f"发送FIN-ACK to {addr}")
                print(f"\n客户端 {addr} 连接释放")
                log_event("INFO", f"连接释放，共接收{total_data_packets}个数据包")
                break

        except socket.timeout:
            log_event("TIMEOUT", "服务器等待超时")
            print("\n服务器等待超时，退出...")
            break
        except Exception as e:
            log_event("ERROR", f"异常: {str(e)}")
            break

    server_socket.close()
    print(f"\n===== Server 关闭 =====")
    print(f"日志已保存至: {os.path.abspath(LOG_FILE)}")


if __name__ == '__main__':
    main()
