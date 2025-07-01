#pragma once
#include "ipc_manager.h"
#include <string>
#include <memory>
#include <thread>
#include <atomic>
#include <pcap.h>

class PacketSniffer {
public:
    explicit PacketSniffer(const std::string& interface);
    ~PacketSniffer();
    
    // ★ 关键修正: 修改初始化方法签名
    bool initialize(const std::string& packet_addr = "", const std::string& command_addr = "");
    bool start_capture();
    void stop_capture();
    
    // 统计信息
    size_t get_total_packets() const;
    size_t get_filtered_packets() const;
    std::string get_interface() const;
    bool is_running() const;

private:
    std::string interface_;
    pcap_t* handle_;
    std::unique_ptr<std::thread> capture_thread_;
    std::unique_ptr<IPCManager> ipc_manager_;
    
    std::atomic<bool> running_;
    std::atomic<size_t> total_packets_;
    std::atomic<size_t> filtered_packets_;
    
    void capture_loop();
    void process_packet(const struct pcap_pkthdr* header, const u_char* packet);
};
