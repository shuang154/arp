#pragma once
#include <zmq.hpp>
#include <memory>
#include <string>
#include <atomic>

struct PacketInfo {
    std::string timestamp;
    std::string src_ip;
    std::string dst_ip;
    std::string src_mac;
    std::string dst_mac;
    std::string protocol;
    int packet_size;
    std::string raw_data;
};

class IPCManager {
public:
    IPCManager();
    ~IPCManager();
    
    // ★ 关键修正: 修改 initialize 方法签名以接受配置参数
    bool initialize(const std::string& packet_addr, const std::string& command_addr);
    void shutdown();
    
    bool send_packet(const PacketInfo& packet);
    bool send_command(const std::string& command);
    bool receive_command(std::string& command, int timeout_ms = 100);
    
    size_t get_packets_sent() const { return packets_sent_.load(); }
    size_t get_commands_sent() const { return commands_sent_.load(); }

private:
    std::unique_ptr<zmq::context_t> context_;
    std::unique_ptr<zmq::socket_t> packet_sender_;
    std::unique_ptr<zmq::socket_t> command_receiver_;
    
    std::atomic<size_t> packets_sent_;
    std::atomic<size_t> commands_sent_;
    bool initialized_;
    
    std::string serialize_packet(const PacketInfo& packet);
};
