#include "config_manager.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <yaml-cpp/yaml.h>

ConfigManager::ConfigManager(const std::string& config_file) 
    : config_file_(config_file), monitoring_(false) {
    // 初始化默认配置
    current_config_ = Config{};
    
    // 获取初始文件修改时间
    try {
        if (std::filesystem::exists(config_file_)) {
            last_modified_ = std::filesystem::last_write_time(config_file_);
        }
    } catch (const std::exception& e) {
        std::cerr << "Warning: Cannot get file modification time: " << e.what() << std::endl;
    }
}

ConfigManager::~ConfigManager() {
    stop_monitoring();
}

bool ConfigManager::load_config() {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    if (!std::filesystem::exists(config_file_)) {
        std::cerr << "Config file not found: " << config_file_ << ". Using default configuration." << std::endl;
        current_config_ = Config{}; // 使用默认值
        return true; 
    }
    
    try {
        std::ifstream file(config_file_);
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string content = buffer.str();
        
        Config new_config;
        if (!parse_yaml_config(content, new_config)) {
            std::cerr << "Failed to parse config file, using previous or default config." << std::endl;
            return false;
        }
        
        current_config_ = new_config;
        std::cout << "Configuration loaded successfully from " << config_file_ << std::endl;
        return true;

    } catch (const std::exception& e) {
        std::cerr << "Error loading config file: " << e.what() << std::endl;
        return false;
    }
}

bool ConfigManager::reload_config() {
    Config old_config = current_config_;
    
    if (!load_config()) {
        return false;
    }
    
    // 检测配置变化
    auto changes = get_config_changes(old_config, current_config_);
    if (!changes.empty()) {
        std::cout << "Configuration changes detected:" << std::endl;
        for (const auto& change : changes) {
            std::cout << "  - " << change << std::endl;
        }
        
        // 通知回调
        notify_callbacks(current_config_);
    }
    
    return true;
}

ConfigManager::Config ConfigManager::get_config() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return current_config_;
}

// ★【实现】★ IPC 配置的 Getters
std::string ConfigManager::get_packet_address() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return current_config_.ipc.packet_address;
}

std::string ConfigManager::get_command_address() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return current_config_.ipc.command_address;
}

std::string ConfigManager::get_heartbeat_address() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return current_config_.ipc.heartbeat_address;
}

std::string ConfigManager::get_heartbeat_pong_address() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return current_config_.ipc.heartbeat_pong_address;
}

int ConfigManager::get_heartbeat_interval() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return current_config_.ipc.heartbeat_interval;
}

int ConfigManager::get_heartbeat_timeout() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return current_config_.ipc.heartbeat_timeout;
}

int ConfigManager::get_packet_hwm() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return current_config_.ipc.packet_hwm;
}

int ConfigManager::get_command_hwm() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return current_config_.ipc.command_hwm;
}

int ConfigManager::get_heartbeat_hwm() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return current_config_.ipc.heartbeat_hwm;
}


void ConfigManager::start_monitoring() {
    if (monitoring_) {
        return;
    }
    
    monitoring_ = true;
    monitor_thread_ = std::make_unique<std::thread>(&ConfigManager::monitor_loop, this);
    std::cout << "Config file monitoring started" << std::endl;
}

void ConfigManager::stop_monitoring() {
    if (!monitoring_) {
        return;
    }
    
    monitoring_ = false;
    if (monitor_thread_ && monitor_thread_->joinable()) {
        monitor_thread_->join();
    }
    std::cout << "Config file monitoring stopped" << std::endl;
}

void ConfigManager::register_change_callback(std::function<void(const Config&)> callback) {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    callbacks_.push_back(callback);
}

void ConfigManager::handle_reload_signal() {
    std::cout << "Received reload signal, reloading configuration..." << std::endl;
    reload_config();
}

bool ConfigManager::validate_config(const Config& config) const {
    // 验证网络配置
    if (config.network.interface.empty()) {
        std::cerr << "Network interface cannot be empty" << std::endl;
        return false;
    }
    
    if (config.network.gateway_ip.empty()) {
        std::cerr << "Gateway IP cannot be empty" << std::endl;
        return false;
    }
    
    // 验证性能配置
    if (config.performance.max_worker_threads <= 0 || 
        config.performance.max_worker_threads > 64) {
        std::cerr << "Invalid worker thread count: " << config.performance.max_worker_threads << std::endl;
        return false;
    }
    
    if (config.performance.packet_buffer_size < 1024 ||
        config.performance.packet_buffer_size > 1073741824) { // 1GB
        std::cerr << "Invalid packet buffer size: " << config.performance.packet_buffer_size << std::endl;
        return false;
    }
    
    // 验证攻击配置
    if (config.attack.attack_timeout <= 0 || config.attack.attack_timeout > 3600) {
        std::cerr << "Invalid attack timeout: " << config.attack.attack_timeout << std::endl;
        return false;
    }
    
    if (config.attack.max_concurrent_attacks <= 0 || 
        config.attack.max_concurrent_attacks > 1000) {
        std::cerr << "Invalid max concurrent attacks: " << config.attack.max_concurrent_attacks << std::endl;
        return false;
    }
    
    return true;
}

std::vector<std::string> ConfigManager::get_config_changes(const Config& old_config, const Config& new_config) const {
    std::vector<std::string> changes;
    
    // 网络配置变化
    if (old_config.network.interface != new_config.network.interface) {
        changes.push_back("Network interface: " + old_config.network.interface + " -> " + new_config.network.interface);
    }
    
    if (old_config.network.gateway_ip != new_config.network.gateway_ip) {
        changes.push_back("Gateway IP: " + old_config.network.gateway_ip + " -> " + new_config.network.gateway_ip);
    }
    
    if (old_config.network.target_server != new_config.network.target_server) {
        changes.push_back("Target server: " + old_config.network.target_server + " -> " + new_config.network.target_server);
    }
    
    // 性能配置变化
    if (old_config.performance.max_worker_threads != new_config.performance.max_worker_threads) {
        changes.push_back("Worker threads: " + std::to_string(old_config.performance.max_worker_threads) + 
                         " -> " + std::to_string(new_config.performance.max_worker_threads));
    }
    
    if (old_config.performance.packet_buffer_size != new_config.performance.packet_buffer_size) {
        changes.push_back("Packet buffer size: " + std::to_string(old_config.performance.packet_buffer_size) + 
                         " -> " + std::to_string(new_config.performance.packet_buffer_size));
    }
    
    // 攻击配置变化
    if (old_config.attack.stealth_mode != new_config.attack.stealth_mode) {
        changes.push_back("Stealth mode: " + std::string(old_config.attack.stealth_mode ? "true" : "false") + 
                         " -> " + std::string(new_config.attack.stealth_mode ? "true" : "false"));
    }
    
    if (old_config.attack.attack_timeout != new_config.attack.attack_timeout) {
        changes.push_back("Attack timeout: " + std::to_string(old_config.attack.attack_timeout) + 
                         " -> " + std::to_string(new_config.attack.attack_timeout));
    }
    
    return changes;
}

void ConfigManager::monitor_loop() {
    while (monitoring_) {
        try {
            if (std::filesystem::exists(config_file_)) {
                auto current_time = get_file_modification_time(config_file_);
                
                if (current_time != last_modified_) {
                    std::cout << "Config file modified, reloading..." << std::endl;
                    last_modified_ = current_time;
                    
                    // 延迟一点时间确保文件写入完成
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    
                    reload_config();
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Error monitoring config file: " << e.what() << std::endl;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}

// ★【重构】★ 使用 yaml-cpp 解析配置
bool ConfigManager::parse_yaml_config(const std::string& content, Config& config) {
    try {
        YAML::Node root = YAML::Load(content);

        // 解析 ipc 部分
        if (root["ipc"]) {
            const auto& ipc_node = root["ipc"];
            config.ipc.packet_address = ipc_node["packet_address"].as<std::string>(config.ipc.packet_address);
            config.ipc.command_address = ipc_node["command_address"].as<std::string>(config.ipc.command_address);
            config.ipc.heartbeat_address = ipc_node["heartbeat_address"].as<std::string>(config.ipc.heartbeat_address);
            config.ipc.heartbeat_pong_address = ipc_node["heartbeat_pong_address"].as<std::string>(config.ipc.heartbeat_pong_address);
            config.ipc.heartbeat_interval = ipc_node["heartbeat_interval"].as<int>(config.ipc.heartbeat_interval);
            config.ipc.heartbeat_timeout = ipc_node["heartbeat_timeout"].as<int>(config.ipc.heartbeat_timeout);
            // ★【关键修复】★ 加载HWM配置
            config.ipc.packet_hwm = ipc_node["packet_hwm"].as<int>(config.ipc.packet_hwm);
            config.ipc.command_hwm = ipc_node["command_hwm"].as<int>(config.ipc.command_hwm);
            config.ipc.heartbeat_hwm = ipc_node["heartbeat_hwm"].as<int>(config.ipc.heartbeat_hwm);
        }

        // 解析 network 部分
        if (root["network"]) {
            const auto& network_node = root["network"];
            config.network.interface = network_node["interface"].as<std::string>(config.network.interface);
            config.network.gateway_ip = network_node["gateway_ip"].as<std::string>(config.network.gateway_ip);
            config.network.target_server = network_node["target_server"].as<std::string>(config.network.target_server);
            
            // 解析端口列表
            if (network_node["target_ports"]) {
                config.network.target_ports.clear();
                for (const auto& port : network_node["target_ports"]) {
                    config.network.target_ports.push_back(port.as<int>());
                }
            }
        }

        // 解析 performance 部分
        if (root["performance"]) {
            const auto& performance_node = root["performance"];
            config.performance.max_worker_threads = performance_node["max_worker_threads"].as<int>(config.performance.max_worker_threads);
            config.performance.packet_buffer_size = performance_node["packet_buffer_size"].as<size_t>(config.performance.packet_buffer_size);
            config.performance.command_timeout = performance_node["command_timeout"].as<int>(config.performance.command_timeout);
        }

        // 解析 attack 部分
        if (root["attack"]) {
            const auto& attack_node = root["attack"];
            config.attack.stealth_mode = attack_node["stealth_mode"].as<bool>(config.attack.stealth_mode);
            config.attack.attack_timeout = attack_node["attack_timeout"].as<int>(config.attack.attack_timeout);
            config.attack.max_concurrent_attacks = attack_node["max_concurrent_attacks"].as<int>(config.attack.max_concurrent_attacks);
            config.attack.cooldown_time = attack_node["cooldown_time"].as<int>(config.attack.cooldown_time);
        }

        // 解析日志级别
        config.log_level = root["log_level"].as<std::string>(config.log_level);

        return true;
    } catch (const YAML::Exception& e) {
        std::cerr << "Failed to parse YAML config: " << e.what() << std::endl;
        return false;
    }
}

void ConfigManager::notify_callbacks(const Config& config) {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    for (const auto& callback : callbacks_) {
        try {
            callback(config);
        } catch (const std::exception& e) {
            std::cerr << "Error in config change callback: " << e.what() << std::endl;
        }
    }
}

decltype(std::filesystem::last_write_time(std::declval<std::string>())) 
ConfigManager::get_file_modification_time(const std::string& file_path) {
    return std::filesystem::last_write_time(file_path);
}
