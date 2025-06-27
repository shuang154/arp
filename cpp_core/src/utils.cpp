#include "utils.h"
#include <unistd.h>
#include <sched.h>
#include <sys/stat.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <cstring>
#include <chrono>

bool bind_to_cpu(int cpu_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);
    
    int result = sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
    if (result == 0) {
        std::cout << "[Utils] Thread bound to CPU " << cpu_id << std::endl;
        return true;
    } else {
        std::cerr << "[Utils] Failed to bind thread to CPU " << cpu_id 
                  << ": " << strerror(errno) << std::endl;
        return false;
    }
}

bool check_root_privileges() {
    return geteuid() == 0;
}

bool check_interface_exists(const std::string& interface) {
    struct ifaddrs *ifaddr, *ifa;
    bool found = false;
    
    if (getifaddrs(&ifaddr) == -1) {
        std::cerr << "[Utils] Failed to get interface list" << std::endl;
        return false;
    }
    
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        
        if (interface == ifa->ifa_name) {
            found = true;
            break;
        }
    }
    
    freeifaddrs(ifaddr);
    return found;
}

std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    
    return ss.str();
}

uint64_t get_timestamp_ms() {
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
}

std::string mac_to_string(const uint8_t* mac) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        if (i > 0) ss << ":";
        ss << std::setw(2) << static_cast<int>(mac[i]);
    }
    return ss.str();
}

bool string_to_mac(const std::string& mac_str, uint8_t* mac) {
    if (mac_str.length() != 17) return false;
    
    std::stringstream ss(mac_str);
    std::string segment;
    int i = 0;
    
    while (std::getline(ss, segment, ':') && i < 6) {
        if (segment.length() != 2) return false;
        
        try {
            mac[i] = static_cast<uint8_t>(std::stoi(segment, nullptr, 16));
            i++;
        } catch (...) {
            return false;
        }
    }
    
    return i == 6;
}

std::string get_system_info() {
    std::stringstream info;
    
    // CPU信息
    info << "CPU Cores: " << get_cpu_count() << "\n";
    
    // 内存信息
    info << "Memory Usage: " << get_memory_usage() << " KB\n";
    
    // 系统时间
    info << "System Time: " << get_timestamp() << "\n";
    
    return info.str();
}

int get_cpu_count() {
    return sysconf(_SC_NPROCESSORS_ONLN);
}

size_t get_memory_usage() {
    std::ifstream status_file("/proc/self/status");
    std::string line;
    size_t memory_kb = 0;
    
    while (std::getline(status_file, line)) {
        if (line.substr(0, 6) == "VmRSS:") {
            std::stringstream ss(line);
            std::string label, value, unit;
            ss >> label >> value >> unit;
            memory_kb = std::stoull(value);
            break;
        }
    }
    
    return memory_kb;
}

std::string get_interface_ip(const std::string& interface) {
    struct ifaddrs *ifaddr, *ifa;
    std::string ip_address;
    
    if (getifaddrs(&ifaddr) == -1) {
        return "";
    }
    
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        
        if (interface == ifa->ifa_name && ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in* addr_in = (struct sockaddr_in*)ifa->ifa_addr;
            ip_address = inet_ntoa(addr_in->sin_addr);
            break;
        }
    }
    
    freeifaddrs(ifaddr);
    return ip_address;
}

std::string get_gateway_ip(const std::string& interface) {
    // 简化实现：读取路由表获取网关IP
    std::ifstream route_file("/proc/net/route");
    std::string line;
    
    // 跳过标题行
    std::getline(route_file, line);
    
    while (std::getline(route_file, line)) {
        std::istringstream iss(line);
        std::string iface, dest, gateway;
        
        iss >> iface >> dest >> gateway;
        
        if (iface == interface && dest == "00000000") {
            // 转换十六进制网关地址
            if (gateway.length() == 8) {
                uint32_t gw_addr = std::stoul(gateway, nullptr, 16);
                struct in_addr addr;
                addr.s_addr = gw_addr;
                return inet_ntoa(addr);
            }
        }
    }
    
    return "";
}
