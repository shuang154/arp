#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <chrono>
#include <vector>

// ★【优化】★ 智能CPU亲和性管理
class CPUAffinityManager {
public:
    struct CPUInfo {
        int total_cores;
        int physical_cores;
        int logical_cores;
        std::vector<int> available_cores;
    };
    
    static CPUInfo get_cpu_info();
    static bool bind_thread_to_core(int core_id);
    static bool bind_current_thread_to_core(int core_id);
    
    // 智能分配CPU核心
    static int allocate_cpu_for_task(const std::string& task_name);
    static void release_cpu_for_task(const std::string& task_name);
    
    // 获取推荐的CPU绑定策略
    static std::vector<int> get_optimal_cpu_distribution(int num_tasks);
};

// CPU亲和性设置
bool bind_to_cpu(int cpu_id);

// 权限检查
bool check_root_privileges();

// 网络接口检查
bool check_interface_exists(const std::string& interface);

// 时间工具
std::string get_timestamp();
uint64_t get_timestamp_ms();

// 字符串工具
std::string mac_to_string(const uint8_t* mac);
bool string_to_mac(const std::string& mac_str, uint8_t* mac);

// 系统信息
std::string get_system_info();
int get_cpu_count();
size_t get_memory_usage();

// ★【新增】★ 系统性能监控
struct SystemStats {
    double cpu_usage_percent;
    size_t memory_used_bytes;
    size_t memory_total_bytes;
    double memory_usage_percent;
    size_t network_rx_bytes;
    size_t network_tx_bytes;
};

SystemStats get_system_stats();

// 网络工具
std::string get_interface_ip(const std::string& interface);
std::string get_gateway_ip(const std::string& interface);

#endif // UTILS_H
