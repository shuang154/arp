#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <chrono>

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

// 网络工具
std::string get_interface_ip(const std::string& interface);
std::string get_gateway_ip(const std::string& interface);

#endif // UTILS_H
