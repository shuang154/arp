#include "packet_sniffer.h"
#include "ipc_manager.h"
#include <iostream>
#include <cstring>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <iomanip> // For std::setprecision and std::fixed

PacketSniffer::PacketSniffer(const std::string& interface, IPCManager* ipc)
    : interface_(interface), handle_(nullptr), ipc_manager_(ipc), 
      running_(false), packets_captured_(0), packets_dropped_(0) {
}

// 添加仅interface的构造函数用于Python绑定
PacketSniffer::PacketSniffer(const std::string& interface)
    : interface_(interface), handle_(nullptr), ipc_manager_(nullptr), 
      running_(false), packets_captured_(0), packets_dropped_(0) {
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
        
        // 获取详细统计信息
        struct pcap_stat stats;
        if (pcap_stats(handle_, &stats) == 0) {
            packets_dropped_ = stats.ps_drop;
            
            // 🔧 增强：计算捕获率和性能指标
            uint64_t total_packets = packets_captured_ + packets_dropped_;
            double capture_rate = total_packets > 0 ? 
                (double)packets_captured_ / total_packets * 100.0 : 0.0;
            
            std::cout << "[Sniffer] ===== Final Performance Report =====" << std::endl;
            std::cout << "[Sniffer] Packets Captured: " << packets_captured_ << std::endl;
            std::cout << "[Sniffer] Packets Dropped: " << packets_dropped_ << std::endl;
            std::cout << "[Sniffer] Total Packets: " << total_packets << std::endl;
            std::cout << "[Sniffer] Capture Rate: " << std::fixed << std::setprecision(2) 
                      << capture_rate << "%" << std::endl;
            
            // 🔧 性能警告机制
            if (capture_rate < 95.0 && packets_dropped_ > 100) {
                std::cout << "[Sniffer] ⚠️  WARNING: Low capture rate detected!" << std::endl;
                std::cout << "[Sniffer] 💡 Consider: Reduce buffer size, increase CPU priority, or optimize filters" << std::endl;
            } else if (capture_rate >= 99.0) {
                std::cout << "[Sniffer] ✅ Excellent capture performance!" << std::endl;
            }
            std::cout << "[Sniffer] =======================================" << std::endl;
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
    
    // 基本数据包信息
    PacketInfo pkt_info;
    pkt_info.timestamp = header->ts;
    pkt_info.length = header->caplen;
    pkt_info.type = PacketType::UNKNOWN;
    
    // 解析以太网头
    if (header->caplen < sizeof(struct ethhdr)) {
        return;
    }
    
    struct ethhdr* eth_header = (struct ethhdr*)packet;
    
    // 检查是否为ARP包
    if (ntohs(eth_header->h_proto) == ETH_P_ARP) {
        if (header->caplen >= sizeof(struct ethhdr) + sizeof(struct ether_arp)) {
            pkt_info.type = PacketType::ARP;
            
            struct ether_arp* arp_header = (struct ether_arp*)(packet + sizeof(struct ethhdr));
            
            // 提取ARP信息
            pkt_info.src_ip = inet_ntoa(*(struct in_addr*)arp_header->arp_spa);
            pkt_info.dst_ip = inet_ntoa(*(struct in_addr*)arp_header->arp_tpa);
            pkt_info.arp_opcode = ntohs(arp_header->arp_op);
            
            // 复制MAC地址
            memcpy(pkt_info.src_mac, arp_header->arp_sha, 6);
            memcpy(pkt_info.dst_mac, arp_header->arp_tha, 6);
        }
    }
    // 检查是否为IP包
    else if (ntohs(eth_header->h_proto) == ETH_P_IP) {
        if (header->caplen < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
            return;
        }
        
        struct iphdr* ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));
        
        // 检查是否为TCP包
        if (ip_header->protocol == IPPROTO_TCP) {
            int ip_header_len = ip_header->ihl * 4;
            if (header->caplen < sizeof(struct ethhdr) + ip_header_len + sizeof(struct tcphdr)) {
                return;
            }
            
            struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ethhdr) + ip_header_len);
            
            // 检查是否为HTTP端口
            uint16_t dst_port = ntohs(tcp_header->dest);
            if (dst_port == 80 || dst_port == 443 || dst_port == 8080 || dst_port == 801) {
                pkt_info.type = PacketType::HTTP;
                
                struct in_addr src_addr, dst_addr;
                src_addr.s_addr = ip_header->saddr;
                dst_addr.s_addr = ip_header->daddr;
                
                pkt_info.src_ip = inet_ntoa(src_addr);
                pkt_info.dst_ip = inet_ntoa(dst_addr);
                pkt_info.src_port = ntohs(tcp_header->source);
                pkt_info.dst_port = dst_port;
                
                // 如果有HTTP数据，复制payload
                int tcp_header_len = tcp_header->doff * 4;
                int total_header_len = sizeof(struct ethhdr) + ip_header_len + tcp_header_len;
                
                if (header->caplen > total_header_len) {
                    int payload_len = header->caplen - total_header_len;
                    if (payload_len > 0 && payload_len < MAX_PAYLOAD_SIZE) {
                        memcpy(pkt_info.payload, packet + total_header_len, payload_len);
                        pkt_info.payload_length = payload_len;
                        pkt_info.payload[payload_len] = '\0';
                    }
                }
            }
        }
    }
    
    // 如果是我们感兴趣的包类型，发送给Python层
    if (pkt_info.type != PacketType::UNKNOWN) {
        if (ipc_manager_) {
            ipc_manager_->send_packet(pkt_info);
        }
    }
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
