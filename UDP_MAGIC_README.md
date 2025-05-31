# UDP Magic 功能说明

UDP Magic 是对原有UDP转发功能的增强版本，它在保留原有主链接的同时，通过多个子链接并行传输数据，从而提高UDP包的传输性能和可靠性。

## 主要特性

1. **多链接并行传输**: 使用主链接和多个子链接同时传输UDP数据
2. **数据包排序**: 自动处理并重新排序从不同链接接收的数据包
3. **负载均衡**: 在多个链接间分配UDP包传输
4. **自动重连**: 子链接断开时自动重新建立
5. **向后兼容**: 可以与原有UDP功能无缝切换

## 实现架构

UDP Magic 功能主要包含以下几个核心组件：

### buffer.go
- `udpDataBlock`: UDP数据块结构，包含数据、序号、源地址和目标地址
- `GlobalUDPBufferTable`: 全局UDP缓冲表，管理不同客户端的数据缓冲
- `udpBlockJoiner`: 数据包重排序器，确保数据包按正确顺序输出

### client.go
- `UDPRelayLocal`: 客户端主要中继函数
- `udpThreadManager`: 子连接管理器，负责创建和管理多个子连接
- `udpDataBlockToConn`: 将数据块写入UDP连接

### server.go
- `UDPRelayRemoteMain`: 服务端主连接处理器
- `UDPRelayRemoteChild`: 服务端子连接处理器
- `udpBufferToLocal`: 将缓冲数据发送到本地连接

### relay.go
- UDP数据包转发和处理功能
- 连接池管理
- 负载均衡算法

### udpmagic.go
- `UDPMagicManager`: UDP Magic 管理器
- 提供统一的API接口
- 配置管理

## 使用方法

### 命令行参数

新增了 `-udpmagic` 参数来启用UDP Magic功能：

```bash
# 启用UDP Magic的服务端
./go-shadowsocks-magic -s :8080 -password mypassword -udpmagic

# 启用UDP Magic的客户端 
./go-shadowsocks-magic -c server_ip:8080 -password mypassword -udpmagic -socks :1080 -u

# 启用UDP Magic的UDP隧道
./go-shadowsocks-magic -c server_ip:8080 -password mypassword -udpmagic -udptun :8053=8.8.8.8:53
```

### 配置选项

UDP Magic 支持以下配置选项：

- `MaxConnections`: 最大子连接数 (默认: 8)
- `Timeout`: 连接超时时间 (默认: 30秒)
- `BufferSize`: 缓冲区大小 (默认: 64KB)
- `EnableLogging`: 是否启用日志 (默认: false)

## 工作原理

### 客户端 (UDP Magic Local)

1. 客户端向服务端发送魔术字节 `0xFF` 请求数据密钥
2. 服务端响应数据密钥 (16字节) 和魔术字节 `0xFE`
3. 客户端使用该密钥创建多个子连接
4. UDP数据包被分配到不同的连接进行传输
5. 数据包携带序号信息，用于重排序

### 服务端 (UDP Magic Remote)

1. 服务端监听主连接，等待客户端的密钥请求
2. 收到请求后生成唯一的数据密钥并发送给客户端
3. 为该客户端创建专用的数据缓冲区
4. 接收来自多个子连接的数据包
5. 将数据包重新排序后转发到目标服务器

### 数据包格式

UDP Magic 使用特殊的数据包格式来支持多连接传输：

```
+----------+----------+-------------+-------------+--------+
| BlockID  | Size     | DestAddrLen | SrcAddrLen  | Data   |
| (4 bytes)| (4 bytes)| (4 bytes)   | (4 bytes)   | (var)  |
+----------+----------+-------------+-------------+--------+
| Destination Address String | Source Address String |
+---------------------------+------------------------+
```

## 与原有功能的兼容性

- 当 `-udpmagic` 参数未指定时，使用原有的UDP转发功能
- 当 `-udpmagic` 参数指定时，使用增强的UDP Magic功能
- 两种模式的API保持一致，可以无缝切换

## 性能优势

1. **并行传输**: 多个连接同时传输数据，提高吞吐量
2. **冗余保护**: 单个连接故障不会影响整体传输
3. **负载分散**: 减少单个连接的负载压力
4. **自适应连接**: 根据需要动态调整连接数量

## 注意事项

1. UDP Magic 需要客户端和服务端都启用才能正常工作
2. 增加的连接数会带来一定的资源开销
3. 建议在高延迟或丢包率较高的网络环境中使用
4. 确保防火墙允许相关端口的UDP流量通过

## 故障排除

如果遇到问题，可以：

1. 启用详细日志: 添加 `-verbose` 参数
2. 检查网络连接和防火墙设置
3. 确认客户端和服务端的参数配置一致
4. 查看错误日志获取详细信息
