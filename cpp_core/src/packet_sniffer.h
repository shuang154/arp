#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include <pcap.h>
#include <string>
#include <atomic>
#include <memory>
#include "object_pool.h"
#include "ipc_manager.h"

// 前向声明PacketInfoPool
class PacketInfoPool;

class PacketSniffer {
private:
    std::string interface_;
    pcap_t* handle_;
    IPCManager* ipc_manager_;
    std::atomic<bool> running_;
    
    // ★【新增】★ 对象池用于高效分配PacketInfo
    std::unique_ptr<PacketInfoPool> packet_info_pool_;
    
    // 统计信息
    std::atomic<uint64_t> packets_captured_;
    std::atomic<uint64_t> packets_dropped_;
    
public:
    PacketSniffer(const std::string& interface, IPCManager* ipc);
    ~PacketSniffer();
    
    bool initialize();
    void start_sniffing();
    void stop();
    
    // 静态回调函数
    static void packet_handler(u_char* user, const struct pcap_pkthdr* header, 
                              const u_char* packet);
    
    // 获取统计信息
    uint64_t get_packets_captured() const { return packets_captured_; }
    uint64_t get_packets_dropped() const { return packets_dropped_; }
    
    // ★【新增】★ 获取对象池统计信息
    void print_pool_stats() const;

private:
    void process_packet(const struct pcap_pkthdr* header, const u_char* packet);
    bool is_arp_packet(const u_char* packet, int len);
    bool is_http_packet(const u_char* packet, int len);
};

#endif // PACKET_SNIFFER_H
