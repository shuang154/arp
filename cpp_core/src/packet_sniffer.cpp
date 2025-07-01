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
    std::cout << "[Packet Sniffer] 🔧 Initializing on interface " << interface_ << std::endl;
    std::cout << "[Packet Sniffer] 🔌 IPC - Packet: " << packet_addr << ", Command: " << command_addr << std::endl;
    
    // ★ 使用传入的地址初始化IPC管理器
    if (!ipc_manager_->initialize(packet_addr, command_addr)) {
        std::cerr << "[Packet Sniffer] ❌ Failed to initialize IPC manager" << std::endl;
        return false;
    }
    
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // 🔧 增加接口检查和调试信息
    std::cout << "[Packet Sniffer] 🔍 Checking interface " << interface_ << "..." << std::endl;
    
    // 打开网络接口进行捕获
    handle_ = pcap_open_live(interface_.c_str(), 65536, 1, 1000, errbuf);
    if (!handle_) {
        std::cerr << "[Packet Sniffer] ❌ Could not open device " << interface_ 
                  << ": " << errbuf << std::endl;
        std::cerr << "[Packet Sniffer] 💡 Troubleshooting tips:" << std::endl;
        std::cerr << "   - Check if interface exists: ip link show" << std::endl;
        std::cerr << "   - Check if running as root: sudo required for packet capture" << std::endl;
        std::cerr << "   - Check if interface is up: ip link set " << interface_ << " up" << std::endl;
        return false;
    }
    
    std::cout << "[Packet Sniffer] ✅ Successfully opened interface " << interface_ << std::endl;
    
    // 设置过滤器：捕获ARP包和常见端口的TCP流量
    struct bpf_program filter;
    const char* filter_exp = "arp or (tcp and (port 80 or port 443 or port 21 or port 22 or port 23 or port 25))";
    
    std::cout << "[Packet Sniffer] 🔍 Setting capture filter: " << filter_exp << std::endl;
    if (pcap_compile(handle_, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "[Packet Sniffer] ❌ Could not parse filter: " << pcap_geterr(handle_) << std::endl;
        pcap_close(handle_);
        handle_ = nullptr;
        return false;
    }
    
    if (pcap_setfilter(handle_, &filter) == -1) {
        std::cerr << "[Packet Sniffer] ❌ Could not install filter: " << pcap_geterr(handle_) << std::endl;
        pcap_freecode(&filter);
        pcap_close(handle_);
        handle_ = nullptr;
        return false;
    }
    
    pcap_freecode(&filter);
    
    std::cout << "[Packet Sniffer] ✅ Initialized successfully with filter: " << filter_exp << std::endl;
    std::cout << "[Packet Sniffer] 🚀 Ready to capture packets from " << interface_ << std::endl;
    return true;
}

// 保持原有的其他方法不变
void PacketSniffer::stop_capture() {
    std::cout << "[Packet Sniffer] 🛑 Stopping packet capture..." << std::endl;
    
    if (running_) {
        running_ = false;
        
        // 通知 pcap_next_ex 退出
        if (handle_) {
            pcap_breakloop(handle_);
        }
        
        if (capture_thread_ && capture_thread_->joinable()) {
            std::cout << "[Packet Sniffer] 🔄 Waiting for capture thread to finish..." << std::endl;
            capture_thread_->join();
            std::cout << "[Packet Sniffer] ✅ Capture thread stopped" << std::endl;
        }
    }
    
    if (handle_) {
        std::cout << "[Packet Sniffer] 🔌 Closing pcap handle..." << std::endl;
        pcap_close(handle_);
        handle_ = nullptr;
    }
    
    if (ipc_manager_) {
        std::cout << "[Packet Sniffer] 🔌 Shutting down IPC manager..." << std::endl;
        ipc_manager_->shutdown();
    }
    
    size_t final_total = total_packets_.load();
    size_t final_filtered = filtered_packets_.load();
    
    std::cout << "[Packet Sniffer] ✅ Stopped capture - Final stats: Total=" << final_total 
              << ", Filtered=" << final_filtered << " (" 
              << (final_total > 0 ? (final_filtered * 100 / final_total) : 0) << "%)" << std::endl;
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
    std::cout << "[Packet Sniffer] 🔄 Starting packet capture loop on " << interface_ << "..." << std::endl;
    
    // 统计相关变量
    auto last_stats_time = std::chrono::steady_clock::now();
    size_t last_total_packets = 0;
    
    while (running_) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        
        int result = pcap_next_ex(handle_, &header, &packet);
        
        if (result == 1) {
            // 成功捕获到包
            total_packets_++;
            process_packet(header, packet);
            
            // 每1000个包输出一次统计信息
            auto current_time = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(current_time - last_stats_time);
            
            if (duration.count() >= 30) {  // 每30秒输出一次统计
                size_t current_total = total_packets_.load();
                size_t current_filtered = filtered_packets_.load();
                size_t packets_per_sec = (current_total - last_total_packets) / std::max(1, (int)duration.count());
                
                std::cout << "[Packet Sniffer] 📊 Stats - Total: " << current_total 
                         << ", Filtered: " << current_filtered 
                         << ", Rate: " << packets_per_sec << " pps" << std::endl;
                
                last_stats_time = current_time;
                last_total_packets = current_total;
            }
            
        } else if (result == 0) {
            // 超时，继续循环
            continue;
        } else if (result == -1) {
            // 错误
            std::cerr << "[Packet Sniffer] ❌ Error reading packet: " << pcap_geterr(handle_) << std::endl;
            break;
        } else if (result == -2) {
            // 到达文件末尾或pcap_breakloop被调用
            std::cout << "[Packet Sniffer] 🛑 Capture stopped (pcap_breakloop called)" << std::endl;
            break;
        }
    }
    
    std::cout << "[Packet Sniffer] 🔚 Capture loop ended - Total packets: " << total_packets_.load() 
              << ", Filtered packets: " << filtered_packets_.load() << std::endl;
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
        pkt_info.type = 1;  // ★ 设置为ARP类型
        
        // 解析ARP包
        struct ether_arp* arp_header = (struct ether_arp*)(packet + sizeof(struct ether_header));
        
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, arp_header->arp_spa, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, arp_header->arp_tpa, dst_ip, INET_ADDRSTRLEN);
        
        pkt_info.src_ip = src_ip;
        pkt_info.dst_ip = dst_ip;
        
        // ★ 关键修正：添加 ARP 操作码信息 
        uint16_t arp_opcode = ntohs(arp_header->ea_hdr.ar_op);
        pkt_info.arp_opcode = arp_opcode;  // ★ 设置操作码到数据结构
        
        if (arp_opcode == 1) {  // ARP请求 (1=请求, 2=应答)
            filtered_packets_++;
            
            // 🔧 每捕获10个ARP包输出一次调试信息
            static size_t arp_debug_counter = 0;
            if (++arp_debug_counter % 10 == 1) {
                std::cout << "[PacketSniffer] 📡 ARP Request captured: " << src_ip << " -> " << dst_ip 
                         << " (Total ARP packets: " << arp_debug_counter << ")" << std::endl;
            }
            
            // 静默发送到Python，只在失败时输出错误
            if (!ipc_manager_->send_packet(pkt_info)) {
                std::cout << "[PacketSniffer] ❌ Failed to send ARP packet: " << src_ip << " -> " << dst_ip << std::endl;
            }
            // 成功时不输出日志，减少冗余
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
            pkt_info.type = 2;  // ★ 设置为HTTP/TCP类型
            
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
                
                // 静默发送到Python，只在失败时输出错误
                if (!ipc_manager_->send_packet(pkt_info)) {
                    std::cout << "[PacketSniffer] ❌ Failed to send TCP packet: " << src_ip << ":" << src_port << " -> " << dst_ip << ":" << dst_port << std::endl;
                }
                // 成功时不输出日志，减少冗余
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
