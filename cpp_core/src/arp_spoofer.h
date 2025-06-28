#ifndef ARP_SPOOFER_H
#define ARP_SPOOFER_H

#include <string>
#include <unordered_map>
#include <thread>
#include <atomic>
#include <mutex>
#include <memory>
#include <vector>

// ARP欺骗会话信息
struct SpoofSession {
    std::string target_ip;
    std::string target_mac;
    std::string gateway_ip;
    std::string gateway_mac;
    std::atomic<bool> active;
    std::unique_ptr<std::thread> spoof_thread;
    uint64_t packets_sent;
    uint64_t start_time;
    
    // ★【新增】★ 定时攻击支持
    uint32_t duration_seconds;  // 攻击持续时间（秒），0表示无限制
    std::string attack_type;    // 攻击类型（scouting, full_attack, standard）
    
    // ★【优化】★ 使用 shared_ptr 管理定时器线程，以便安全地传递给lambda
    std::shared_ptr<std::thread> timer_thread;  
    std::atomic<bool> timer_active;             // 定时器是否活跃
};

class ARPSpoofer {
private:
    std::string interface_;
    int raw_socket_;
    
    // 活跃的欺骗会话
    std::unordered_map<std::string, std::shared_ptr<SpoofSession>> active_sessions_;
    mutable std::mutex sessions_mutex_;  // 添加mutable关键字
    
    // 统计信息
    std::atomic<uint64_t> total_packets_sent_;
    std::atomic<uint64_t> total_sessions_;
    
public:
    ARPSpoofer(const std::string& interface);
    ~ARPSpoofer();
    
    bool initialize();
    void shutdown();
    
    // 开始对目标进行ARP欺骗
    bool start_spoofing(const std::string& target_ip, const std::string& gateway_ip,
                       const std::string& target_mac, const std::string& gateway_mac,
                       uint32_t duration_seconds = 0, const std::string& attack_type = "standard");
    
    // 停止对目标的ARP欺骗
    bool stop_spoofing(const std::string& target_ip);
    
    // 恢复目标的ARP表
    bool restore_arp(const std::string& target_ip, const std::string& gateway_ip,
                    const std::string& target_mac, const std::string& gateway_mac);
    
    // 获取统计信息
    uint64_t get_total_packets_sent() const { return total_packets_sent_; }
    uint64_t get_total_sessions() const { return total_sessions_; }
    size_t get_active_sessions_count() const;
    
    // 获取活跃会话信息
    std::vector<std::string> get_active_targets() const;

private:
    // 创建原始套接字
    bool create_raw_socket();
    
    // 发送单个ARP包
    bool send_arp_packet(const std::string& src_ip, const std::string& src_mac,
                        const std::string& dst_ip, const std::string& dst_mac,
                        uint16_t operation);
    
    // 欺骗线程函数
    void spoof_thread_func(const std::string& target_ip);
    
    // ★【新增】★ 定时器线程函数
    void timer_thread_func(const std::string& target_ip, uint32_t duration_seconds, 
                          std::weak_ptr<SpoofSession> session_weak_ptr);
    
    // 获取本机MAC地址
    std::string get_interface_mac();
    
    // 工具函数
    bool parse_mac_address(const std::string& mac_str, uint8_t* mac_bytes);
    bool parse_ip_address(const std::string& ip_str, uint32_t* ip_addr);
};

#endif // ARP_SPOOFER_H
