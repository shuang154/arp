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
#include <unordered_map>
#include <algorithm>
#include <mutex>

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

// ★【新增】★ 智能CPU亲和性管理器实现
static std::unordered_map<std::string, int> task_cpu_map;
static std::mutex task_cpu_mutex;

CPUAffinityManager::CPUInfo CPUAffinityManager::get_cpu_info() {
    CPUInfo info;
    
    // 获取总核心数
    info.total_cores = get_cpu_count();
    
    // 简化实现：假设物理核心数是逻辑核心数的一半（对于支持超线程的CPU）
    info.logical_cores = info.total_cores;
    info.physical_cores = std::max(1, info.total_cores / 2);
    
    // 构建可用核心列表
    for (int i = 0; i < info.total_cores; ++i) {
        info.available_cores.push_back(i);
    }
    
    return info;
}

bool CPUAffinityManager::bind_thread_to_core(int core_id) {
    return bind_to_cpu(core_id);
}

bool CPUAffinityManager::bind_current_thread_to_core(int core_id) {
    return bind_to_cpu(core_id);
}

int CPUAffinityManager::allocate_cpu_for_task(const std::string& task_name) {
    std::lock_guard<std::mutex> lock(task_cpu_mutex);
    
    auto cpu_info = get_cpu_info();
    
    // 智能分配策略
    if (task_name == "packet_sniffer") {
        // 数据包嗅探：优先使用第一个物理核心
        int target_cpu = 0;
        task_cpu_map[task_name] = target_cpu;
        return target_cpu;
    } else if (task_name == "ipc_handler") {
        // IPC处理：使用第二个物理核心
        int target_cpu = std::min(1, cpu_info.total_cores - 1);
        task_cpu_map[task_name] = target_cpu;
        return target_cpu;
    } else if (task_name == "arp_spoofer") {
        // ARP欺骗：使用第三个核心或回到第一个
        int target_cpu = cpu_info.total_cores > 2 ? 2 : 0;
        task_cpu_map[task_name] = target_cpu;
        return target_cpu;
    } else {
        // 其他任务：轮询分配
        int target_cpu = task_cpu_map.size() % cpu_info.total_cores;
        task_cpu_map[task_name] = target_cpu;
        return target_cpu;
    }
}

void CPUAffinityManager::release_cpu_for_task(const std::string& task_name) {
    std::lock_guard<std::mutex> lock(task_cpu_mutex);
    task_cpu_map.erase(task_name);
}

std::vector<int> CPUAffinityManager::get_optimal_cpu_distribution(int num_tasks) {
    auto cpu_info = get_cpu_info();
    std::vector<int> distribution;
    
    if (num_tasks <= cpu_info.total_cores) {
        // 如果任务数少于核心数，每个任务分配一个核心
        for (int i = 0; i < num_tasks; ++i) {
            distribution.push_back(i % cpu_info.total_cores);
        }
    } else {
        // 如果任务数多于核心数，均匀分配
        for (int i = 0; i < num_tasks; ++i) {
            distribution.push_back(i % cpu_info.total_cores);
        }
    }
    
    return distribution;
}

// ★【优化】★ 系统性能监控实现
SystemStats get_system_stats() {
    SystemStats stats = {0};
    
    // 获取内存使用情况
    stats.memory_used_bytes = get_memory_usage();
    
    // 简化实现：读取/proc/meminfo获取总内存
    std::ifstream meminfo("/proc/meminfo");
    if (meminfo.is_open()) {
        std::string line;
        while (std::getline(meminfo, line)) {
            if (line.find("MemTotal:") == 0) {
                std::istringstream iss(line);
                std::string label;
                size_t value;
                std::string unit;
                if (iss >> label >> value >> unit) {
                    stats.memory_total_bytes = value * 1024; // 转换为字节
                    break;
                }
            }
        }
        meminfo.close();
    }
    
    if (stats.memory_total_bytes > 0) {
        stats.memory_usage_percent = 
            (static_cast<double>(stats.memory_used_bytes) / stats.memory_total_bytes) * 100.0;
    }
    
    // 简化实现：CPU使用率（这里返回一个估计值）
    stats.cpu_usage_percent = 0.0; // 实际实现需要读取/proc/stat
    
    return stats;
}
