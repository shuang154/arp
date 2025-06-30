#include "real_network_capture.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <chrono>
#include <net/ethernet.h>
#include <netinet/ether.h>

RealNetworkCapture::~RealNetworkCapture() {
    stop_capture();
}

bool RealNetworkCapture::initialize(const std::string& iface, const std::string& filter) {
    if (initialized) {
        stop_capture();
    }
    
    interface = iface;
    filter_expression = filter;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // 打开网络接口
    pcap_handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!pcap_handle) {
        std::cerr << "❌ Failed to open interface " << interface << ": " << errbuf << std::endl;
        return false;
    }
    
    std::cout << "✅ Successfully opened network interface: " << interface << std::endl;
    
    // 设置过滤器（如果提供）
    if (!filter_expression.empty()) {
        struct bpf_program fp;
        if (pcap_compile(pcap_handle, &fp, filter_expression.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "❌ Failed to compile filter: " << pcap_geterr(pcap_handle) << std::endl;
            pcap_close(pcap_handle);
            pcap_handle = nullptr;
            return false;
        }
        
        if (pcap_setfilter(pcap_handle, &fp) == -1) {
            std::cerr << "❌ Failed to set filter: " << pcap_geterr(pcap_handle) << std::endl;
            pcap_freecode(&fp);
            pcap_close(pcap_handle);
            pcap_handle = nullptr;
            return false;
        }
        
        pcap_freecode(&fp);
        std::cout << "✅ Filter applied: " << filter_expression << std::endl;
    }
    
    initialized = true;
    std::cout << "✅ Network capture initialized successfully" << std::endl;
    return true;
}

void RealNetworkCapture::set_packet_callback(PacketCallback callback) {
    packet_callback = callback;
}

bool RealNetworkCapture::start_capture() {
    if (!initialized || !pcap_handle) {
        std::cerr << "❌ Network capture not initialized" << std::endl;
        return false;
    }
    
    if (capturing) {
        std::cerr << "⚠️ Already capturing" << std::endl;
        return true;
    }
    
    capturing = true;
    std::cout << "🚀 Starting packet capture on " << interface << std::endl;
    
    // 开始捕获循环
    int result = pcap_loop(pcap_handle, -1, packet_handler, reinterpret_cast<u_char*>(this));
    
    if (result == -1) {
        std::cerr << "❌ Error during packet capture: " << pcap_geterr(pcap_handle) << std::endl;
        capturing = false;
        return false;
    }
    
    capturing = false;
    std::cout << "🛑 Packet capture stopped" << std::endl;
    return true;
}

bool RealNetworkCapture::capture_next_packet() {
    if (!initialized || !pcap_handle) {
        return false;
    }
    
    struct pcap_pkthdr* header;
    const u_char* packet;
    
    int result = pcap_next_ex(pcap_handle, &header, &packet);
    
    if (result == 1) {
        // 成功捕获一个数据包
        if (packet_callback) {
            PacketInfo info;
            info.packet_size = header->len;
            info.timestamp = header->ts.tv_sec + header->ts.tv_usec / 1000000.0;
            
            // 解析数据包
            parse_ethernet_header(packet, info);
            
            // 调用回调函数
            packet_callback(info);
        }
        return true;
    } else if (result == 0) {
        // 超时，没有数据包
        return false;
    } else {
        // 错误
        std::cerr << "❌ Error capturing packet: " << pcap_geterr(pcap_handle) << std::endl;
        return false;
    }
}

void RealNetworkCapture::stop_capture() {
    if (pcap_handle) {
        if (capturing) {
            std::cout << "🛑 Stopping packet capture..." << std::endl;
            pcap_breakloop(pcap_handle);
            capturing = false;
        }
        pcap_close(pcap_handle);
        pcap_handle = nullptr;
    }
    initialized = false;
}

std::string RealNetworkCapture::get_last_error() const {
    if (pcap_handle) {
        return pcap_geterr(pcap_handle);
    }
    return "No error information available";
}

void RealNetworkCapture::packet_handler(u_char* user_data, const struct pcap_pkthdr* header, const u_char* packet) {
    RealNetworkCapture* capture = reinterpret_cast<RealNetworkCapture*>(user_data);
    
    if (capture && capture->packet_callback) {
        PacketInfo info;
        info.packet_size = header->len;
        info.timestamp = header->ts.tv_sec + header->ts.tv_usec / 1000000.0;
        
        // 解析数据包
        capture->parse_ethernet_header(packet, info);
        
        // 调用回调函数
        capture->packet_callback(info);
    }
}

bool RealNetworkCapture::parse_ethernet_header(const u_char* packet, PacketInfo& info) {
    if (!packet) return false;
    
    const struct ether_header* eth_header = reinterpret_cast<const struct ether_header*>(packet);
    
    // 提取源和目标MAC地址
    info.source_mac = mac_to_string(eth_header->ether_shost);
    info.dest_mac = mac_to_string(eth_header->ether_dhost);
    
    uint16_t eth_type = ntohs(eth_header->ether_type);
    
    if (eth_type == ETHERTYPE_ARP) {
        info.is_arp = true;
        info.protocol = "ARP";
        return parse_arp_packet(packet + sizeof(struct ether_header), info);
    } else if (eth_type == ETHERTYPE_IP) {
        info.protocol = "IP";
        return parse_ip_packet(packet + sizeof(struct ether_header), 
                              info.packet_size - sizeof(struct ether_header), info);
    }
    
    return true;
}

bool RealNetworkCapture::parse_arp_packet(const u_char* packet, PacketInfo& info) {
    if (!packet) return false;
    
    // ARP包结构
    struct arp_header {
        uint16_t ar_hrd;    // Hardware type
        uint16_t ar_pro;    // Protocol type
        uint8_t ar_hln;     // Hardware length
        uint8_t ar_pln;     // Protocol length
        uint16_t ar_op;     // Operation
        uint8_t ar_sha[6];  // Sender hardware address
        uint8_t ar_spa[4];  // Sender protocol address
        uint8_t ar_tha[6];  // Target hardware address
        uint8_t ar_tpa[4];  // Target protocol address
    };
    
    const struct arp_header* arp = reinterpret_cast<const struct arp_header*>(packet);
    
    // 提取IP地址
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, arp->ar_spa, source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp->ar_tpa, dest_ip, INET_ADDRSTRLEN);
    
    info.source_ip = source_ip;
    info.dest_ip = dest_ip;
    
    return true;
}

bool RealNetworkCapture::parse_ip_packet(const u_char* packet, size_t packet_len, PacketInfo& info) {
    if (!packet || packet_len < sizeof(struct iphdr)) {
        return false;
    }
    
    const struct iphdr* ip = reinterpret_cast<const struct iphdr*>(packet);
    
    // 提取源和目标IP地址
    struct in_addr src_addr, dest_addr;
    src_addr.s_addr = ip->saddr;
    dest_addr.s_addr = ip->daddr;
    
    info.source_ip = inet_ntoa(src_addr);
    info.dest_ip = inet_ntoa(dest_addr);
    
    // 检查协议类型
    if (ip->protocol == IPPROTO_TCP) {
        info.is_tcp = true;
        info.protocol = "TCP";
        
        // 解析TCP头部获取端口
        size_t ip_header_len = ip->ihl * 4;
        if (packet_len >= ip_header_len + sizeof(struct tcphdr)) {
            const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(packet + ip_header_len);
            info.source_port = ntohs(tcp->source);
            info.dest_port = ntohs(tcp->dest);
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        info.is_udp = true;
        info.protocol = "UDP";
        
        // 解析UDP头部获取端口
        size_t ip_header_len = ip->ihl * 4;
        if (packet_len >= ip_header_len + sizeof(struct udphdr)) {
            const struct udphdr* udp = reinterpret_cast<const struct udphdr*>(packet + ip_header_len);
            info.source_port = ntohs(udp->source);
            info.dest_port = ntohs(udp->dest);
        }
    }
    
    return true;
}

std::string RealNetworkCapture::mac_to_string(const u_char* mac) {
    std::stringstream ss;
    for (int i = 0; i < 6; ++i) {
        if (i > 0) ss << ":";
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
    }
    return ss.str();
}

std::vector<std::string> RealNetworkCapture::get_available_interfaces() {
    std::vector<std::string> interfaces;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "❌ Error finding devices: " << errbuf << std::endl;
        return interfaces;
    }
    
    for (pcap_if_t* dev = alldevs; dev; dev = dev->next) {
        interfaces.push_back(dev->name);
    }
    
    pcap_freealldevs(alldevs);
    return interfaces;
}
