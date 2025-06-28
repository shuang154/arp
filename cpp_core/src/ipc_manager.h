#ifndef IPC_MANAGER_H
#define IPC_MANAGER_H

#include <zmq.hpp>
#include <string>
#include <memory>
#include <chrono>
#include <optional>
#include <atomic>
#include <thread>
#include <functional>

// 数据包类型枚举
enum class PacketType {
    UNKNOWN = 0,
    ARP = 1,
    HTTP = 2
};

// 命令类型枚举
enum class CommandType {
    START_SPOOF = 1,
    STOP_SPOOF = 2,
    RESTORE_ARP = 3,
    PING = 4,        // 心跳ping
    PONG = 5,        // 心跳pong
    SHUTDOWN = 6     // 优雅停机
};

// 常量定义
static const int MAX_PAYLOAD_SIZE = 8192;

// 数据包信息结构
struct PacketInfo {
    struct timeval timestamp;
    PacketType type;
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint16_t arp_opcode = 0;
    uint8_t src_mac[6] = {0};
    uint8_t dst_mac[6] = {0};
    uint32_t length = 0;
    
    char payload[MAX_PAYLOAD_SIZE] = {0};
    uint32_t payload_length = 0;
    
    // ★【新增】★ 重置函数，供对象池使用
    void reset() {
        timestamp = {0, 0};
        type = PacketType::UNKNOWN;
        src_ip.clear();
        dst_ip.clear();
        src_port = 0;
        dst_port = 0;
        arp_opcode = 0;
        memset(src_mac, 0, 6);
        memset(dst_mac, 0, 6);
        length = 0;
        memset(payload, 0, MAX_PAYLOAD_SIZE);
        payload_length = 0;
    }
};

// IPC命令结构
struct IPCCommand {
    CommandType type;
    std::string target_ip;
    std::string gateway_ip;
    std::string target_mac;
    std::string gateway_mac;
    uint32_t duration = 0;
    std::string attack_type = "standard";  // ★【新增】★ 攻击类型
    std::string reason = "";               // ★【新增】★ 决策原因
};

class IPCManager {
private:
    std::unique_ptr<zmq::context_t> context_;
    std::unique_ptr<zmq::socket_t> packet_sender_;    // 发送数据包给Python
    std::unique_ptr<zmq::socket_t> command_receiver_; // 接收Python的命令
    
    bool initialized_;
    uint64_t packets_sent_;
    uint64_t commands_received_;
    
    // ★【新增】★ 心跳机制
    std::atomic<bool> heartbeat_running_;
    std::unique_ptr<std::thread> heartbeat_thread_;
    std::chrono::steady_clock::time_point last_ping_time_;
    std::chrono::steady_clock::time_point last_pong_time_;
    std::function<void()> connection_lost_callback_;
    
    static constexpr int HEARTBEAT_INTERVAL_MS = 10000;   // 10秒发送一次心跳（降低频率）
    static constexpr int HEARTBEAT_TIMEOUT_MS = 30000;    // 30秒超时（增加容忍度）

public:
    IPCManager();
    ~IPCManager();
    
    bool initialize();
    void shutdown();
    
    // 发送数据包给Python层
    bool send_packet(const PacketInfo& packet);
    
    // 接收Python层的命令
    std::optional<IPCCommand> receive_command(int timeout_ms = 1);
    
    // ★【新增】★ 心跳相关方法
    void start_heartbeat();
    void stop_heartbeat();
    bool is_connection_healthy() const;
    void set_connection_lost_callback(std::function<void()> callback);
    
    // 获取统计信息
    uint64_t get_packets_sent() const { return packets_sent_; }
    uint64_t get_commands_received() const { return commands_received_; }
    
    // ★【新增】★ 获取心跳状态
    struct HeartbeatStatus {
        bool is_healthy;
        std::chrono::milliseconds last_ping_ago;
        std::chrono::milliseconds last_pong_ago;
        uint64_t total_pings_sent;
        uint64_t total_pongs_received;
    };
    HeartbeatStatus get_heartbeat_status() const;

private:
    std::string serialize_packet(const PacketInfo& packet);
    std::optional<IPCCommand> deserialize_command(const std::string& data);
    
    // ★【新增】★ 心跳相关私有方法
    void heartbeat_loop();
    bool send_ping();
    void handle_pong();
    
    // 心跳统计
    std::atomic<uint64_t> pings_sent_;
    std::atomic<uint64_t> pongs_received_;
};

#endif // IPC_MANAGER_H
