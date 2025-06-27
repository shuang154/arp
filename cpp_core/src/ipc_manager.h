#ifndef IPC_MANAGER_H
#define IPC_MANAGER_H

#include <zmq.hpp>
#include <string>
#include <memory>
#include <chrono>
#include <optional>

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
    RESTORE_ARP = 3
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
};

// IPC命令结构
struct IPCCommand {
    CommandType type;
    std::string target_ip;
    std::string gateway_ip;
    std::string target_mac;
    std::string gateway_mac;
    uint32_t duration = 0;
};

class IPCManager {
private:
    std::unique_ptr<zmq::context_t> context_;
    std::unique_ptr<zmq::socket_t> packet_sender_;    // 发送数据包给Python
    std::unique_ptr<zmq::socket_t> command_receiver_; // 接收Python的命令
    
    bool initialized_;
    uint64_t packets_sent_;
    uint64_t commands_received_;

public:
    IPCManager();
    ~IPCManager();
    
    bool initialize();
    void shutdown();
    
    // 发送数据包给Python层
    bool send_packet(const PacketInfo& packet);
    
    // 接收Python层的命令
    std::optional<IPCCommand> receive_command(int timeout_ms = 1);
    
    // 获取统计信息
    uint64_t get_packets_sent() const { return packets_sent_; }
    uint64_t get_commands_received() const { return commands_received_; }

private:
    std::string serialize_packet(const PacketInfo& packet);
    std::optional<IPCCommand> deserialize_command(const std::string& data);
};

#endif // IPC_MANAGER_H
