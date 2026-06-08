============================================================
UDP Socket 编程实习 - 模拟TCP可靠传输
============================================================

一、运行环境
------------
- Python 3.7+
- 依赖库：pandas（用于RTT统计）
  安装命令：pip install pandas

二、文件说明
------------
- udpserver.py      : UDP服务器端程序
- udpclient.py      : UDP客户端程序
- run_log.txt       : 客户端运行日志（自动生成）
- run_log_server.txt: 服务器端运行日志（自动生成）
- README.md         : 本说明文档

三、运行步骤
------------
1. 启动服务器（在终端1）：
   python udpserver.py <port>
   示例：python udpserver.py 12000

2. 启动客户端（在终端2）：
   python udpclient.py <serverIP> <serverPort>
   示例：python udpclient.py 127.0.0.1 12000

3. 观察输出：
   - 客户端会显示发送/确认/重传信息
   - 服务器会显示接收/丢包/确认信息
   - 双方各自生成日志文件

四、配置选项
------------
【服务器端 udpserver.py】
- LOSS_RATE = 0.3        : 丢包率（0.0-1.0），默认30%
- BUFFER_SIZE = 2048     : 接收缓冲区大小

【客户端 udpclient.py】
- TIMEOUT_MS = 300       : 初始超时时间（毫秒），运行中自适应调整
- WINDOW_SIZE = 400      : 发送窗口大小（字节）
- MIN_PKT_SIZE = 40      : 最小数据包大小
- MAX_PKT_SIZE = 80      : 最大数据包大小
- TOTAL_PACKETS = 30     : 需要发送的数据包总数
- STUDENT_ID_SUFFIX      : 学号后4位（请修改为你的学号）

五、协议设计说明
---------------
自定义应用层协议首部（10字节）：

| 字段      | 大小   | 说明                          |
|-----------|--------|-------------------------------|
| 类型      | 1字节  | SYN/SYN-ACK/DATA/ACK/FIN/FIN-ACK |
| 标志      | 1字节  | 重传/累积确认标志              |
| 序列号    | 2字节  | 数据包序列号                   |
| 确认号    | 2字节  | 累积确认号（GBN）              |
| 数据长度  | 2字节  | 数据部分长度                   |
| StudentID | 2字节  | 学号后4位 XOR 0x5A3C           |

ACK报文数据部分携带服务器系统时间（HH-MM-SS格式，8字节）。

六、核心机制
-----------
1. 连接建立：三次握手模拟（SYN → SYN-ACK → ACK）
2. 连接释放：两次挥手模拟（FIN → FIN-ACK）
3. 可靠传输：GBN协议 + 超时重传 + 累积确认
4. 丢包模拟：服务器随机丢弃数据包（不响应）
5. 自适应超时：根据历史RTT动态调整超时时间（avg_rtt * 2，范围100ms~5000ms）
6. 服务器时间：ACK中携带服务器系统时间，客户端显示

七、日志说明
-----------
客户端日志文件 run_log.txt 记录所有事件：
- [SEND]    : 发送数据包
- [RECV]    : 接收数据包
- [ACKED]   : 确认数据包
- [RETRANS] : 重传数据包
- [DROP]    : 模拟丢包
- [TIMEOUT] : 超时事件
- [STATS]   : 统计信息

服务器日志文件 run_log_server.txt 记录服务器端事件。

八、注意事项
-----------
1. 请修改 udpclient.py 中的 STUDENT_ID_SUFFIX 为你的真实学号后4位
2. 确保服务器先于客户端启动
3. 如果运行在同一台机器，serverIP使用 127.0.0.1
4. 日志文件会自动生成，不要手动编辑
5. 可用Wireshark抓包验证（过滤条件：udp.port == <port>）
