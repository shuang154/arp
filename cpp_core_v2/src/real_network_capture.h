#pragma once

#include <pcap.h>
#include <string>
#include <functional>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

/**
 * 真实网络数据包捕获器
 * 使用 libpcap 实现真正的网络接口数据包捕获
 */
class RealNetworkCapture {
public:
    struct PacketInfo {
        std::string source_ip;
        std::string dest_ip;
        std::string source_mac;
        std::string dest_mac;
        uint16_t source_port = 0;
        uint16_t dest_port = 0;
        std::string protocol;
        size_t packet_size = 0;
        double timestamp = 0.0;
        bool is_arp = false;
        bool is_tcp = false;
        bool is_udp = false;
    };

    using PacketCallback = std::function<void(const PacketInfo&)>;

private:
    pcap_t* pcap_handle = nullptr;
    std::string interface;
    std::string filter_expression;
    PacketCallback packet_callback;
    bool initialized = false;
    bool capturing = false;
    
    // 数据包解析回调
    static void packet_handler(u_char* user_data, const struct pcap_pkthdr* header, const u_char* packet);
    
    // 解析以太网头部
    bool parse_ethernet_header(const u_char* packet, PacketInfo& info);
    
    // 解析ARP包
    bool parse_arp_packet(const u_char* packet, PacketInfo& info);
    
    // 解析IP包
    bool parse_ip_packet(const u_char* packet, size_t packet_len, PacketInfo& info);
    
    // MAC地址转字符串
    std::string mac_to_string(const u_char* mac);
    
public:
    RealNetworkCapture() = default;
    ~RealNetworkCapture();
    
    // 初始化网络接口
    bool initialize(const std::string& iface, const std::string& filter = "");
    
    // 设置数据包回调函数
    void set_packet_callback(PacketCallback callback);
    
    // 开始捕获（阻塞模式）
    bool start_capture();
    
    // 开始捕获（非阻塞模式，捕获一个包就返回）
    bool capture_next_packet();
    
    // 停止捕获
    void stop_capture();
    
    // 获取错误信息
    std::string get_last_error() const;
    
    // 检查是否正在捕获
    bool is_capturing() const { return capturing; }
    
    // 获取网络接口信息
    static std::vector<std::string> get_available_interfaces();
};
