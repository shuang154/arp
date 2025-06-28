#include "packet_sniffer.h"
#include "ipc_manager.h"
#include <iostream>
#include <cstring>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <chrono>
#include <mutex>
#include <algorithm>

PacketSniffer::PacketSniffer(const std::string& interface, IPCManager* ipc)
    : interface_(interface), handle_(nullptr), ipc_manager_(ipc), 
      running_(false), packets_captured_(0), packets_dropped_(0), packets_throttled_(0),
      token_bucket_(100), last_refill_time_(std::chrono::steady_clock::now()) {  // ★【流量控制】★ 初始化令牌桶
    
    // ★【新增】★ 初始化PacketInfo对象池（预分配1000个对象，最大5000个）
    packet_info_pool_ = std::make_unique<PacketInfoPool>(1000, 5000);
    std::cout << "[Sniffer] Initialized PacketInfo object pool (1000 initial, 5000 max)" << std::endl;
    std::cout << "[Sniffer] ★【流量控制】★ Token bucket initialized: " << max_tokens_ << " max tokens, " << refill_rate_ << " tokens/sec" << std::endl;
}

PacketSniffer::~PacketSniffer() {
    stop();
}

bool PacketSniffer::initialize() {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // 创建捕获句柄
    handle_ = pcap_create(interface_.c_str(), errbuf);
    if (!handle_) {
        std::cerr << "[Sniffer] Failed to create pcap handle: " << errbuf << std::endl;
        return false;
    }
    
    // 设置立即模式以降低延迟
    if (pcap_set_immediate_mode(handle_, 1) != 0) {
        std::cerr << "[Sniffer] Warning: Failed to set immediate mode" << std::endl;
    }
    
    // 设置缓冲区大小 (16MB)
    if (pcap_set_buffer_size(handle_, 16 * 1024 * 1024) != 0) {
        std::cerr << "[Sniffer] Warning: Failed to set buffer size" << std::endl;
    }
    
    // 设置混杂模式
    if (pcap_set_promisc(handle_, 1) != 0) {
        std::cerr << "[Sniffer] Warning: Failed to set promiscuous mode" << std::endl;
    }
    
    // 设置超时时间
    if (pcap_set_timeout(handle_, 1000) != 0) {
        std::cerr << "[Sniffer] Warning: Failed to set timeout" << std::endl;
    }
    
    // 激活句柄
    int ret = pcap_activate(handle_);
    if (ret != 0) {
        std::cerr << "[Sniffer] Failed to activate pcap handle: " 
                  << pcap_geterr(handle_) << std::endl;
        pcap_close(handle_);
        handle_ = nullptr;
        return false;
    }
    
    // 设置BPF过滤器 - 捕获ARP和HTTP流量
    struct bpf_program fp;
    const char* filter_exp = "arp or (tcp and (port 80 or port 443 or port 8080 or port 801))";
    
    if (pcap_compile(handle_, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "[Sniffer] Failed to compile filter: " << pcap_geterr(handle_) << std::endl;
        pcap_close(handle_);
        handle_ = nullptr;
        return false;
    }
    
    if (pcap_setfilter(handle_, &fp) == -1) {
        std::cerr << "[Sniffer] Failed to set filter: " << pcap_geterr(handle_) << std::endl;
        pcap_freecode(&fp);
        pcap_close(handle_);
        handle_ = nullptr;
        return false;
    }
    
    pcap_freecode(&fp);
    
    std::cout << "[Sniffer] Initialized on interface " << interface_ 
              << " with filter: " << filter_exp << std::endl;
    return true;
}

void PacketSniffer::start_sniffing() {
    if (!handle_) {
        std::cerr << "[Sniffer] Cannot start sniffing: not initialized" << std::endl;
        return;
    }
    
    running_ = true;
    std::cout << "[Sniffer] Starting packet capture loop..." << std::endl;
    
    // 开始捕获循环
    pcap_loop(handle_, -1, packet_handler, reinterpret_cast<u_char*>(this));
}

void PacketSniffer::stop() {
    if (running_ && handle_) {
        running_ = false;
        pcap_breakloop(handle_);
        
        // 获取统计信息
        struct pcap_stat stats;
        if (pcap_stats(handle_, &stats) == 0) {
            packets_dropped_ = stats.ps_drop;
            std::cout << "[Sniffer] Final stats - Captured: " << packets_captured_
                      << ", Dropped: " << packets_dropped_ << std::endl;
        }
        
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

void PacketSniffer::packet_handler(u_char* user, const struct pcap_pkthdr* header,
                                  const u_char* packet) {
    PacketSniffer* sniffer = reinterpret_cast<PacketSniffer*>(user);
    if (sniffer && sniffer->running_) {
        sniffer->process_packet(header, packet);
    }
}

void PacketSniffer::process_packet(const struct pcap_pkthdr* header, const u_char* packet) {
    packets_captured_++;
    
    // ★【流量控制】★ 尝试获取令牌，如果没有令牌则丢弃包
    if (!try_acquire_token()) {
        packets_throttled_++;
        // 每1000个被限流的包输出一次警告
        if (packets_throttled_ % 1000 == 0) {
            std::cout << "[Sniffer] ⚠️ Traffic throttled: " << packets_throttled_ << " packets dropped due to rate limiting" << std::endl;
        }
        return;
    }
    
    // ★【优化】★ 使用对象池分配PacketInfo，避免频繁内存分配
    auto pkt_info = packet_info_pool_->acquire();
    if (!pkt_info) {
        std::cerr << "[Sniffer] Failed to acquire PacketInfo from pool" << std::endl;
        return;
    }
    
    // 重置对象状态（对象池会自动调用reset，但为了保险再次调用）
    pkt_info->reset();
    
    // 基本数据包信息
    pkt_info->timestamp = header->ts;
    pkt_info->length = header->caplen;
    pkt_info->type = PacketType::UNKNOWN;
    
    // 解析以太网头
    if (header->caplen < sizeof(struct ethhdr)) {
        // 将对象归还到池中
        packet_info_pool_->release(std::move(pkt_info));
        return;
    }
    
    struct ethhdr* eth_header = (struct ethhdr*)packet;
    
    // 检查是否为ARP包
    if (ntohs(eth_header->h_proto) == ETH_P_ARP) {
        if (header->caplen >= sizeof(struct ethhdr) + sizeof(struct ether_arp)) {
            pkt_info->type = PacketType::ARP;
            
            struct ether_arp* arp_header = (struct ether_arp*)(packet + sizeof(struct ethhdr));
            
            // 提取ARP信息
            pkt_info->src_ip = inet_ntoa(*(struct in_addr*)arp_header->arp_spa);
            pkt_info->dst_ip = inet_ntoa(*(struct in_addr*)arp_header->arp_tpa);
            pkt_info->arp_opcode = ntohs(arp_header->arp_op);
            
            // 复制MAC地址
            memcpy(pkt_info->src_mac, arp_header->arp_sha, 6);
            memcpy(pkt_info->dst_mac, arp_header->arp_tha, 6);
        }
    }
    // 检查是否为IP包
    else if (ntohs(eth_header->h_proto) == ETH_P_IP) {
        if (header->caplen < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
            packet_info_pool_->release(std::move(pkt_info));
            return;
        }
        
        struct iphdr* ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));
        
        // 检查是否为TCP包
        if (ip_header->protocol == IPPROTO_TCP) {
            int ip_header_len = ip_header->ihl * 4;
            if (header->caplen < sizeof(struct ethhdr) + ip_header_len + sizeof(struct tcphdr)) {
                packet_info_pool_->release(std::move(pkt_info));
                return;
            }
            
            struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ethhdr) + ip_header_len);
            
            // 检查是否为HTTP端口
            uint16_t dst_port = ntohs(tcp_header->dest);
            if (dst_port == 80 || dst_port == 443 || dst_port == 8080 || dst_port == 801) {
                pkt_info->type = PacketType::HTTP;
                
                struct in_addr src_addr, dst_addr;
                src_addr.s_addr = ip_header->saddr;
                dst_addr.s_addr = ip_header->daddr;
                
                pkt_info->src_ip = inet_ntoa(src_addr);
                pkt_info->dst_ip = inet_ntoa(dst_addr);
                pkt_info->src_port = ntohs(tcp_header->source);
                pkt_info->dst_port = dst_port;
                
                // 如果有HTTP数据，复制payload
                int tcp_header_len = tcp_header->doff * 4;
                int total_header_len = sizeof(struct ethhdr) + ip_header_len + tcp_header_len;
                
                if (header->caplen > total_header_len) {
                    int payload_len = header->caplen - total_header_len;
                    if (payload_len > 0 && payload_len < MAX_PAYLOAD_SIZE) {
                        memcpy(pkt_info->payload, packet + total_header_len, payload_len);
                        pkt_info->payload_length = payload_len;
                        pkt_info->payload[payload_len] = '\0';
                    }
                }
            }
        }
    }
    
    // 如果是我们感兴趣的包类型，发送给Python层
    if (pkt_info->type != PacketType::UNKNOWN) {
        if (ipc_manager_) {
            // 发送数据包（IPCManager会复制数据，所以可以安全归还对象）
            ipc_manager_->send_packet(*pkt_info);
        }
    }
    
    // ★【关键】★ 将对象归还到池中以供重复使用
    packet_info_pool_->release(std::move(pkt_info));
}

bool PacketSniffer::is_arp_packet(const u_char* packet, int len) {
    if (len < sizeof(struct ethhdr)) return false;
    struct ethhdr* eth_header = (struct ethhdr*)packet;
    return ntohs(eth_header->h_proto) == ETH_P_ARP;
}

bool PacketSniffer::is_http_packet(const u_char* packet, int len) {
    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)) {
        return false;
    }
    
    struct ethhdr* eth_header = (struct ethhdr*)packet;
    if (ntohs(eth_header->h_proto) != ETH_P_IP) return false;
    
    struct iphdr* ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));
    if (ip_header->protocol != IPPROTO_TCP) return false;
    
    int ip_header_len = ip_header->ihl * 4;
    struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ethhdr) + ip_header_len);
    
    uint16_t dst_port = ntohs(tcp_header->dest);
    return (dst_port == 80 || dst_port == 443 || dst_port == 8080 || dst_port == 801);
}

// ★【新增】★ 打印对象池统计信息
void PacketSniffer::print_pool_stats() const {
    if (packet_info_pool_) {
        auto stats = packet_info_pool_->get_stats();
        std::cout << "[Sniffer] PacketInfo Pool Stats:" << std::endl
                  << "  Current Size: " << stats.current_size << std::endl
                  << "  Objects Created: " << stats.objects_created << std::endl
                  << "  Objects Reused: " << stats.objects_reused << std::endl
                  << "  Pool Hits: " << stats.pool_hits << std::endl
                  << "  Pool Misses: " << stats.pool_misses << std::endl
                  << "  Hit Ratio: " << (stats.hit_ratio * 100) << "%" << std::endl;
    }
}

// ★【流量控制】★ 令牌桶实现
bool PacketSniffer::try_acquire_token() {
    std::lock_guard<std::mutex> lock(bucket_mutex_);
    
    // 补充令牌
    refill_tokens();
    
    // 尝试获取令牌
    if (token_bucket_.load() > 0) {
        token_bucket_--;
        return true;
    }
    
    return false;  // 没有令牌，丢弃数据包
}

void PacketSniffer::refill_tokens() {
    auto now = std::chrono::steady_clock::now();
    auto time_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_refill_time_).count();
    
    if (time_elapsed >= 100) {  // 每100ms补充一次令牌
        int tokens_to_add = (refill_rate_ * time_elapsed) / 1000;  // 按时间比例补充
        int current_tokens = token_bucket_.load();
        int new_tokens = std::min(current_tokens + tokens_to_add, max_tokens_);
        
        token_bucket_.store(new_tokens);
        last_refill_time_ = now;
        
        // 每5秒输出一次令牌桶状态（调试用）
        static auto last_debug_time = now;
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_debug_time).count() >= 5) {
            std::cout << "[Sniffer] 🪣 Token bucket: " << new_tokens << "/" << max_tokens_ 
                      << " tokens, throttled: " << packets_throttled_ << " packets" << std::endl;
            last_debug_time = now;
        }
    }
}