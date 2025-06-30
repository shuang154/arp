#pragma once

#include <string>
#include <vector>
#include <fstream>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

/**
 * 真实ARP攻击器
 * 使用原始套接字发送ARP欺骗包
 */
class RealARPAttacker {
public:
    struct AttackTarget {
        std::string target_ip;
        std::string target_mac;
        std::string gateway_ip;
        std::string gateway_mac;
        std::string interface;
        uint32_t session_id;
        double start_time;
        bool active = false;
    };

private:
    int raw_socket = -1;
    std::string interface;
    std::string local_mac;
    std::string local_ip;
    int interface_index = -1;
    bool initialized = false;
    
    // 获取本地MAC地址
    bool get_local_mac_address();
    
    // 获取本地IP地址
    bool get_local_ip_address();
    
    // 发送ARP包
    bool send_arp_packet(const std::string& src_ip, const std::string& src_mac,
                        const std::string& dst_ip, const std::string& dst_mac,
                        uint16_t op_code);
    
    // 构造ARP包
    std::vector<uint8_t> build_arp_packet(const std::string& src_ip, const std::string& src_mac,
                                         const std::string& dst_ip, const std::string& dst_mac,
                                         uint16_t op_code);
    
    // MAC地址字符串转字节数组
    bool mac_string_to_bytes(const std::string& mac_str, uint8_t* mac_bytes);
    
    // IP地址字符串转字节数组
    bool ip_string_to_bytes(const std::string& ip_str, uint8_t* ip_bytes);
    
    // 记录攻击日志到临时文件
    void log_attack_to_temp_file(const AttackTarget& target, const std::string& action);

public:
    RealARPAttacker() = default;
    ~RealARPAttacker();
    
    // 初始化攻击器
    bool initialize(const std::string& iface);
    
    // 执行ARP欺骗攻击
    bool execute_attack(const AttackTarget& target);
    
    // 发送ARP请求获取MAC地址
    std::string resolve_mac_address(const std::string& ip);
    
    // 停止所有攻击
    void stop_all_attacks();
    
    // 获取本地网络信息
    std::string get_local_mac() const { return local_mac; }
    std::string get_local_ip() const { return local_ip; }
    
    // 检查是否已初始化
    bool is_initialized() const { return initialized; }
    
    // 获取错误信息
    std::string get_last_error() const;
};
