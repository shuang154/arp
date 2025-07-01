#include "packet_sniffer.h"
#include "utils.h"
#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <cstring>

PacketSniffer::PacketSniffer(const std::string& interface) 
    : interface_(interface), handle_(nullptr), capture_thread_(nullptr), 
      running_(false), total_packets_(0), filtered_packets_(0) {
    
    ipc_manager_ = std::make_unique<IPCManager>();
}

PacketSniffer::~PacketSniffer() {
    stop_capture();
}

// ★ 关键修正: 修改初始化方法以接受IPC配置
bool PacketSniffer::initialize(const std::string& packet_addr, const std::string& command_addr) {
    std::cout << "[Packet Sniffer] Initializing on interface " << interface_ << std::endl;
    std::cout << "[Packet Sniffer] IPC - Packet: " << packet_addr << ", Command: " << command_addr << std::endl;
    
    // ★ 使用传入的地址初始化IPC管理器
    if (!ipc_manager_->initialize(packet_addr, command_addr)) {
        std::cerr << "[Packet Sniffer] Failed to initialize IPC manager" << std::endl;
        return false;
    }
    
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // 打开网络接口进行捕获
    handle_ = pcap_open_live(interface_.c_str(), 65536, 1, 1000, errbuf);
    if (!handle_) {
        std::cerr << "[Packet Sniffer] Could not open device " << interface_ 
                  << ": " << errbuf << std::endl;
        return false;
    }
    
    // 设置过滤器：捕获ARP包和常见端口的TCP流量
    struct bpf_program filter;
    const char* filter_exp = "arp or (tcp and (port 80 or port 443 or port 21 or port 22 or port 23 or port 25))";
    
    if (pcap_compile(handle_, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "[Packet Sniffer] Could not parse filter: " << pcap_geterr(handle_) << std::endl;
        pcap_close(handle_);
        handle_ = nullptr;
        return false;
    }
    
    if (pcap_setfilter(handle_, &filter) == -1) {
        std::cerr << "[Packet Sniffer] Could not install filter: " << pcap_geterr(handle_) << std::endl;
        pcap_freecode(&filter);
        pcap_close(handle_);
        handle_ = nullptr;
        return false;
    }
    
    pcap_freecode(&filter);
    
    std::cout << "[Packet Sniffer] Initialized successfully with filter: " << filter_exp << std::endl;
    return true;
}

// 保持原有的其他方法不变
void PacketSniffer::stop_capture() {
    if (running_) {
        running_ = false;
        if (capture_thread_ && capture_thread_->joinable()) {
            capture_thread_->join();
        }
    }
    
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
    
    if (ipc_manager_) {
        ipc_manager_->shutdown();
    }
    
    std::cout << "[Packet Sniffer] Stopped capture" << std::endl;
}

bool PacketSniffer::start_capture() {
    if (!handle_) {
        std::cerr << "[Packet Sniffer] Not initialized" << std::endl;
        return false;
    }
    
    if (running_) {
        std::cout << "[Packet Sniffer] Already capturing" << std::endl;
        return true;
    }
    
    running_ = true;
    capture_thread_ = std::make_unique<std::thread>(&PacketSniffer::capture_loop, this);
    
    std::cout << "[Packet Sniffer] Started packet capture" << std::endl;
    return true;
}

void PacketSniffer::capture_loop() {
    std::cout << "[Packet Sniffer] Starting packet capture loop..." << std::endl;
    
    while (running_) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        
        int result = pcap_next_ex(handle_, &header, &packet);
        
        if (result == 1) {
            // 成功捕获到包
            total_packets_++;
            process_packet(header, packet);
        } else if (result == 0) {
            // 超时，继续循环
            continue;
        } else if (result == -1) {
            // 错误
            std::cerr << "[Packet Sniffer] Error reading packet: " << pcap_geterr(handle_) << std::endl;
            break;
        } else if (result == -2) {
            // 到达文件末尾或pcap_breakloop被调用
            break;
        }
    }
    
    std::cout << "[Packet Sniffer] Capture loop ended" << std::endl;
}

void PacketSniffer::process_packet(const struct pcap_pkthdr* header, const u_char* packet) {
    PacketInfo pkt_info;
    
    // 解析以太网头
    struct ether_header* eth_header = (struct ether_header*)packet;
    
    // 转换MAC地址
    pkt_info.src_mac = mac_to_string(eth_header->ether_shost);
    pkt_info.dst_mac = mac_to_string(eth_header->ether_dhost);
    pkt_info.timestamp = get_timestamp_ms();
    pkt_info.packet_size = header->len;
    
    uint16_t ether_type = ntohs(eth_header->ether_type);
    
    if (ether_type == ETHERTYPE_ARP) {
        pkt_info.protocol = "ARP";
        // 解析ARP包
        struct ether_arp* arp_header = (struct ether_arp*)(packet + sizeof(struct ether_header));
        
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, arp_header->arp_spa, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, arp_header->arp_tpa, dst_ip, INET_ADDRSTRLEN);
        
        pkt_info.src_ip = src_ip;
        pkt_info.dst_ip = dst_ip;
        
        filtered_packets_++;
        
        // 发送到Python进行分析
        std::cout << "[PacketSniffer] Sending ARP packet to Python: " << src_ip << " -> " << dst_ip << std::endl;
        if (!ipc_manager_->send_packet(pkt_info)) {
            std::cout << "[PacketSniffer] Failed to send ARP packet to Python" << std::endl;
        } else {
            std::cout << "[PacketSniffer] Successfully sent ARP packet to Python" << std::endl;
        }
        
    } else if (ether_type == ETHERTYPE_IP) {
        // 解析IP包
        struct iphdr* ip_header = (struct iphdr*)(packet + sizeof(struct ether_header));
        
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_header->saddr, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip_header->daddr, dst_ip, INET_ADDRSTRLEN);
        
        pkt_info.src_ip = src_ip;
        pkt_info.dst_ip = dst_ip;
        
        if (ip_header->protocol == IPPROTO_TCP) {
            pkt_info.protocol = "TCP";
            
            // 可以进一步解析TCP头以获取端口信息
            struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + (ip_header->ihl * 4));
            uint16_t src_port = ntohs(tcp_header->source);
            uint16_t dst_port = ntohs(tcp_header->dest);
            
            // 检查是否是我们感兴趣的端口
            if (src_port == 80 || dst_port == 80 || src_port == 443 || dst_port == 443 ||
                src_port == 21 || dst_port == 21 || src_port == 22 || dst_port == 22 ||
                src_port == 23 || dst_port == 23 || src_port == 25 || dst_port == 25) {
                
                filtered_packets_++;
                
                // 如果需要，可以提取HTTP数据等
                pkt_info.raw_data = std::string((char*)packet, std::min((int)header->len, 200)); // 只保存前200字节
                
                // 发送到Python进行分析
                std::cout << "[PacketSniffer] Sending TCP packet to Python: " << src_ip << ":" << src_port << " -> " << dst_ip << ":" << dst_port << std::endl;
                if (!ipc_manager_->send_packet(pkt_info)) {
                    std::cout << "[PacketSniffer] Failed to send TCP packet to Python" << std::endl;
                } else {
                    std::cout << "[PacketSniffer] Successfully sent TCP packet to Python" << std::endl;
                }
            }
        }
    }
}

size_t PacketSniffer::get_total_packets() const {
    return total_packets_.load();
}

size_t PacketSniffer::get_filtered_packets() const {
    return filtered_packets_.load();
}

std::string PacketSniffer::get_interface() const {
    return interface_;
}

bool PacketSniffer::is_running() const {
    return running_;
}
