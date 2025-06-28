#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <filesystem>
#include <vector>
#include <type_traits>

/**
 * 配置热重载管理器
 * 支持配置文件变化监听和信号驱动的配置重载
 */
class ConfigManager {
public:
    struct NetworkConfig {
        std::string interface = "wlan0";
        std::string gateway_ip = "192.168.1.1";
        std::string target_server = "192.168.1.100";
        std::vector<int> target_ports = {80, 443, 8080, 801};
    };
    
    struct PerformanceConfig {
        int max_worker_threads = 8;
        size_t packet_buffer_size = 8388608;  // 8MB
        int command_timeout = 1000;
    };
    
    struct AttackConfig {
        bool stealth_mode = false;
        int attack_timeout = 45;
        int max_concurrent_attacks = 20;
        int cooldown_time = 3600;
    };
    
    // ★【新增】★ IPC配置
    struct IPCConfig {
        std::string packet_address = "ipc:///tmp/arp_spoofer_packets.ipc";
        std::string command_address = "ipc:///tmp/arp_spoofer_commands.ipc";
        std::string heartbeat_address = "ipc:///tmp/arp_spoofer_heartbeat_ping.ipc";
        std::string heartbeat_pong_address = "ipc:///tmp/arp_spoofer_heartbeat_pong.ipc";
        int heartbeat_interval = 5000;   // ms
        int heartbeat_timeout = 20000;   // ms
        // ★【关键修复】★ HWM配置
        int packet_hwm = 1000;          // 数据包通道HWM
        int command_hwm = 500;          // 命令通道HWM
        int heartbeat_hwm = 1;          // 心跳通道HWM，设为1防止堆积
    };

    struct Config {
        IPCConfig ipc; // ★ 使用新的IPCConfig结构体
        NetworkConfig network;
        PerformanceConfig performance;
        AttackConfig attack;
        std::string log_level = "INFO";
        int web_api_port = 8080;
        
        // 新增：CPU亲和性配置
        bool enable_cpu_binding = true;
        int sniffer_cpu = 1;
        int ipc_cpu = 2;
        int main_cpu = 0;
    };

private:
    std::string config_file_;
    Config current_config_;
    mutable std::mutex config_mutex_;
    
    // 配置变化监听
    std::atomic<bool> monitoring_;
    std::unique_ptr<std::thread> monitor_thread_;
    decltype(std::filesystem::last_write_time(std::declval<std::string>())) last_modified_;
    
    // 配置变化回调
    std::vector<std::function<void(const Config&)>> callbacks_;
    std::mutex callbacks_mutex_;

public:
    ConfigManager(const std::string& config_file);
    ~ConfigManager();
    
    // 加载配置
    bool load_config();
    bool reload_config();
    
    // 获取配置
    Config get_config() const;
    NetworkConfig get_network_config() const;
    PerformanceConfig get_performance_config() const;
    AttackConfig get_attack_config() const;

    // ★【新增】★ IPC配置的Getters
    std::string get_packet_address() const;
    std::string get_command_address() const;
    std::string get_heartbeat_address() const;
    std::string get_heartbeat_pong_address() const;
    int get_heartbeat_interval() const;
    int get_heartbeat_timeout() const;
    // ★【关键修复】★ HWM配置获取方法
    int get_packet_hwm() const;
    int get_command_hwm() const;
    int get_heartbeat_hwm() const;
    
    // 配置变化监听
    void start_monitoring();
    void stop_monitoring();
    void register_change_callback(std::function<void(const Config&)> callback);
    
    // 信号处理（SIGHUP重载配置）
    void handle_reload_signal();
    
    // 配置验证
    bool validate_config(const Config& config) const;
    
    // 配置差异检测
    std::vector<std::string> get_config_changes(const Config& old_config, const Config& new_config) const;

private:
    void monitor_loop();
    bool parse_yaml_config(const std::string& content, Config& config);
    void notify_callbacks(const Config& config);
    decltype(std::filesystem::last_write_time(std::declval<std::string>())) get_file_modification_time(const std::string& file_path);
};

#endif // CONFIG_MANAGER_H
