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
#include "config_manager.h" // ★ 包含config manager

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
public:
    // ★【修改】★ 构造函数接收ConfigManager，不再需要单独的init
    IPCManager(const ConfigManager& config);
    ~IPCManager();

    // 禁止拷贝和赋值
    IPCManager(const IPCManager&) = delete;
    IPCManager& operator=(const IPCManager&) = delete;

    // ★【修改】★ receive_command现在只接收业务命令
    std::optional<IPCCommand> receive_command(int timeout_ms = 1);
    
    bool send_packet(const PacketInfo& packet);

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
    void heartbeat_thread_func();
    void handle_pong();

    // ★【修改】★ 序列化/反序列化移到私有
    std::string serialize_packet(const PacketInfo& packet);
    std::optional<IPCCommand> deserialize_command(const std::string& data);

    const ConfigManager& config_; // ★【新增】★ 持有配置引用

    // ★【修改】★ 拆分不同的ZMQ Context和Socket
    std::unique_ptr<zmq::context_t> main_context_;
    std::unique_ptr<zmq::context_t> heartbeat_context_;

    std::unique_ptr<zmq::socket_t> packet_sender_;      // PUSH to python (packets)
    std::unique_ptr<zmq::socket_t> command_receiver_;   // PULL from python (commands)
    
    // ★【修改】★ 明确心跳通道的 PING 发送和 PONG 接收
    std::unique_ptr<zmq::socket_t> heartbeat_ping_sender_; // PUSH to python (PING)
    std::unique_ptr<zmq::socket_t> heartbeat_pong_receiver_; // PULL from python (PONG)

    std::atomic<bool> shutdown_flag_{false};

    // Heartbeat state
    std::thread heartbeat_thread_;
    std::atomic<bool> heartbeat_running_{false};
    std::atomic<std::chrono::steady_clock::time_point> last_pong_time_;
    std::function<void()> connection_lost_callback_;
    
    // Stats
    std::atomic<uint64_t> packets_sent_{0};
    std::atomic<uint64_t> commands_received_{0};
    std::atomic<uint64_t> pings_sent_{0};
    std::atomic<uint64_t> pongs_received_{0};
};

#endif // IPC_MANAGER_H
