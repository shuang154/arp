#include "config_manager.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <csignal>
#include <algorithm>
#include <regex>

ConfigManager::ConfigManager(const std::string& config_file) 
    : config_file_(config_file), monitoring_(false) {
    // 初始化默认配置
    current_config_ = Config{};
    
    // 获取初始文件修改时间
    try {
        if (std::filesystem::exists(config_file_)) {
            last_modified_ = get_file_modification_time(config_file_);
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
        std::cerr << "Config file not found: " << config_file_ << std::endl;
        std::cerr << "Using default configuration" << std::endl;
        return true; // 使用默认配置
    }
    
    std::ifstream file(config_file_);
    if (!file.is_open()) {
        std::cerr << "Failed to open config file: " << config_file_ << std::endl;
        return false;
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    
    Config new_config;
    if (!parse_yaml_config(content, new_config)) {
        std::cerr << "Failed to parse config file" << std::endl;
        return false;
    }
    
    if (!validate_config(new_config)) {
        std::cerr << "Config validation failed" << std::endl;
        return false;
    }
    
    current_config_ = new_config;
    std::cout << "Configuration loaded successfully" << std::endl;
    
    return true;
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

ConfigManager::NetworkConfig ConfigManager::get_network_config() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return current_config_.network;
}

ConfigManager::PerformanceConfig ConfigManager::get_performance_config() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return current_config_.performance;
}

ConfigManager::AttackConfig ConfigManager::get_attack_config() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return current_config_.attack;
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

bool ConfigManager::parse_yaml_config(const std::string& content, Config& config) {
    // 简化的YAML解析器 - 支持基本的键值对
    std::istringstream stream(content);
    std::string line;
    std::string current_section;
    
    while (std::getline(stream, line)) {
        // 移除前后空白
        line.erase(0, line.find_first_not_of(" \t"));
        line.erase(line.find_last_not_of(" \t") + 1);
        
        // 跳过空行和注释
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        // 检查是否为section
        if (line.back() == ':' && line.find(' ') == std::string::npos) {
            current_section = line.substr(0, line.length() - 1);
            continue;
        }
        
        // 解析键值对
        size_t colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string key = line.substr(0, colon_pos);
            std::string value = line.substr(colon_pos + 1);
            
            // 移除空白
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            
            // 根据section和key设置配置
            if (current_section == "network") {
                if (key == "interface") config.network.interface = value;
                else if (key == "gateway_ip") config.network.gateway_ip = value;
                else if (key == "target_server") config.network.target_server = value;
                else if (key == "target_ports") {
                    // 解析端口列表 [80, 443, 8080]
                    config.network.target_ports.clear();
                    std::regex port_regex(R"(\d+)");
                    std::sregex_iterator iter(value.begin(), value.end(), port_regex);
                    std::sregex_iterator end;
                    
                    for (; iter != end; ++iter) {
                        config.network.target_ports.push_back(std::stoi(iter->str()));
                    }
                }
            } else if (current_section == "performance") {
                if (key == "max_worker_threads") config.performance.max_worker_threads = std::stoi(value);
                else if (key == "packet_buffer_size") config.performance.packet_buffer_size = std::stoull(value);
                else if (key == "command_timeout") config.performance.command_timeout = std::stoi(value);
            } else if (current_section == "attack") {
                if (key == "stealth_mode") config.attack.stealth_mode = (value == "true" || value == "1");
                else if (key == "attack_timeout") config.attack.attack_timeout = std::stoi(value);
                else if (key == "max_concurrent_attacks") config.attack.max_concurrent_attacks = std::stoi(value);
                else if (key == "cooldown_time") config.attack.cooldown_time = std::stoi(value);
            } else if (current_section.empty()) {
                // 顶级配置
                if (key == "log_level") config.log_level = value;
                else if (key == "web_api_port") config.web_api_port = std::stoi(value);
                else if (key == "enable_cpu_binding") config.enable_cpu_binding = (value == "true" || value == "1");
                else if (key == "sniffer_cpu") config.sniffer_cpu = std::stoi(value);
                else if (key == "ipc_cpu") config.ipc_cpu = std::stoi(value);
                else if (key == "main_cpu") config.main_cpu = std::stoi(value);
            }
        }
    }
    
    return true;
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
