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
    
    // ★【流量控制】★ 令牌桶限流机制
    std::atomic<int> token_bucket_;           // 当前令牌数
    std::chrono::steady_clock::time_point last_refill_time_;  // 上次补充令牌时间
    const int max_tokens_ = 100;             // 最大令牌数
    const int refill_rate_ = 50;             // 每秒补充令牌数
    std::mutex bucket_mutex_;                // 令牌桶互斥锁
    
    // 统计信息
    std::atomic<uint64_t> packets_captured_;
    std::atomic<uint64_t> packets_dropped_;
    std::atomic<uint64_t> packets_throttled_;  // ★【新增】★ 被限流丢弃的包数
    
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
    uint64_t get_packets_throttled() const { return packets_throttled_; }  // ★【新增】★
    
    // ★【新增】★ 获取对象池统计信息
    void print_pool_stats() const;

private:
    void process_packet(const struct pcap_pkthdr* header, const u_char* packet);
    bool is_arp_packet(const u_char* packet, int len);
    bool is_http_packet(const u_char* packet, int len);
    
    // ★【流量控制】★ 令牌桶相关方法
    bool try_acquire_token();                // 尝试获取令牌
    void refill_tokens();                    // 补充令牌
};

#endif // PACKET_SNIFFER_H
