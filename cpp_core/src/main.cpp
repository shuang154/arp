#include <iostream>
#include <signal.h>
#include <unistd.h>
#include <thread>
#include <memory>
#include <chrono>
#include "packet_sniffer.h"
#include "arp_spoofer.h"
#include "ipc_manager.h"
#include "utils.h"
// #include "graceful_shutdown.h"  // ★【临时注释】★ 未完整实现
#include "config_manager.h"
#include "object_pool.h"

class ARPSpooferCore {
private:
    std::unique_ptr<PacketSniffer> sniffer_;
    std::unique_ptr<ARPSpoofer> spoofer_;
    std::unique_ptr<IPCManager> ipc_;
    std::unique_ptr<ConfigManager> config_;
    // std::unique_ptr<GracefulShutdownManager> shutdown_manager_;  // ★【临时注释】★ 未完整实现
    
    std::atomic<bool> running_;
    std::string interface_;
    
    // ★【保留】★ 性能监控
    std::thread monitoring_thread_;
    std::chrono::steady_clock::time_point start_time_;

public:
    ARPSpooferCore(const std::string& iface) 
        : interface_(iface), running_(true) {
        
        // 初始化配置管理器
        config_ = std::make_unique<ConfigManager>("../config/config.yaml");
        // shutdown_manager_ = std::make_unique<GracefulShutdownManager>();  // ★【临时注释】★ 未完整实现
        
        // 初始化IPC管理器
        ipc_ = std::make_unique<IPCManager>();
        
        // 初始化ARP欺骗器
        spoofer_ = std::make_unique<ARPSpoofer>(interface_);
        
        // 初始化数据包嗅探器
        sniffer_ = std::make_unique<PacketSniffer>(interface_, ipc_.get());
        
        start_time_ = std::chrono::steady_clock::now();
    }
    
    bool initialize() {
        std::cout << "[C++ Core] 🚀 Initializing ARP Spoofer Pro v2.0..." << std::endl;
        
        if (!check_root_privileges()) {
            std::cerr << "[ERROR] This program requires root privileges!" << std::endl;
            return false;
        }
        
        // 加载配置
        if (!config_->load_config()) {
            std::cerr << "[WARNING] Failed to load config, using defaults" << std::endl;
        }
        
        // 启动配置监控
        config_->start_monitoring();
        
        // 设置优雅停机
        setup_graceful_shutdown();
        
        if (!ipc_->initialize()) {
            std::cerr << "[ERROR] Failed to initialize IPC!" << std::endl;
            return false;
        }
        
        // 设置连接丢失回调，但暂时不启动心跳
        ipc_->set_connection_lost_callback([this]() {
            std::cerr << "[ERROR] 💔 Lost connection to Python supervisor!" << std::endl;
        });
        
        if (!sniffer_->initialize()) {
            std::cerr << "[ERROR] Failed to initialize packet sniffer!" << std::endl;
            return false;
        }
        
        if (!spoofer_->initialize()) {
            std::cerr << "[ERROR] Failed to initialize ARP spoofer!" << std::endl;
            return false;
        }
        
        std::cout << "[C++ Core] ✅ Core modules initialized successfully" << std::endl;
        print_system_info();
        
        return true;
    }
    
    void run() {
        std::cout << "[C++ Core] 🚀 Starting optimized main loop..." << std::endl;
        
        // 等待Python端启动并启动心跳机制
        std::cout << "[C++ Core] Waiting for Python supervisor to be ready..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(3));  // 等待3秒
        
        // 现在启动心跳机制
        ipc_->start_heartbeat();
        std::cout << "[C++ Core] Heartbeat mechanism started" << std::endl;
        
        auto cfg = config_->get_config();
        
        // ★【优化】★ 智能CPU亲和性分配
        auto cpu_manager = CPUAffinityManager::get_cpu_info();
        std::cout << "[CPU] Available cores: " << cpu_manager.total_cores 
                  << " (physical: " << cpu_manager.physical_cores << ")" << std::endl;
        
        // 启动嗅探线程
        std::thread sniffer_thread([this, cfg]() {
            int cpu = cfg.enable_cpu_binding ? cfg.sniffer_cpu : -1;
            if (cpu >= 0) {
                CPUAffinityManager::bind_current_thread_to_core(cpu);
                std::cout << "[Sniffer] 📌 Bound to CPU core " << cpu << std::endl;
            }
            sniffer_->start_sniffing();
        });
        
        // 启动IPC命令处理循环
        std::thread ipc_thread([this, cfg]() {
            int cpu = cfg.enable_cpu_binding ? cfg.ipc_cpu : -1;
            if (cpu >= 0) {
                CPUAffinityManager::bind_current_thread_to_core(cpu);
                std::cout << "[IPC] 📌 Bound to CPU core " << cpu << std::endl;
            }
            
            while (running_) {
                auto command = ipc_->receive_command();
                if (command) {
                    handle_command(*command);
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        });
        
        // ★【新增】★ 启动性能监控线程
        monitoring_thread_ = std::thread([this]() {
            performance_monitoring_loop();
        });
        
        // 主线程等待停机信号
        while (running_) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        std::cout << "[C++ Core] 🛑 Shutdown signal received, starting graceful shutdown..." << std::endl;
        
        // 清理线程
        sniffer_->stop();
        if (sniffer_thread.joinable()) sniffer_thread.join();
        if (ipc_thread.joinable()) ipc_thread.join();
        if (monitoring_thread_.joinable()) monitoring_thread_.join();
        
        // 停止心跳
        ipc_->stop_heartbeat();
        
        std::cout << "[C++ Core] ✅ Shutdown complete" << std::endl;
    }
    
    void stop() {
        running_ = false;
    }

private:
    void handle_command(const IPCCommand& cmd) {
        switch (cmd.type) {
            case CommandType::START_SPOOF:
                spoofer_->start_spoofing(cmd.target_ip, cmd.gateway_ip, 
                                       cmd.target_mac, cmd.gateway_mac);
                break;
            case CommandType::STOP_SPOOF:
                spoofer_->stop_spoofing(cmd.target_ip);
                break;
            case CommandType::RESTORE_ARP:
                spoofer_->restore_arp(cmd.target_ip, cmd.gateway_ip,
                                    cmd.target_mac, cmd.gateway_mac);
                break;
            case CommandType::PONG:
                // 心跳响应已在IPC管理器中处理
                break;
            case CommandType::SHUTDOWN:
                std::cout << "[C++ Core] Received shutdown command from Python" << std::endl;
                stop();
                break;
            default:
                std::cerr << "[WARNING] Unknown command type: " << static_cast<int>(cmd.type) << std::endl;
        }
    }
    
    // ★【临时注释】★ 优雅停机功能暂时不可用
    void setup_graceful_shutdown() {
        // 简化版本 - 仅设置信号处理
        std::cout << "[Setup] Graceful shutdown configured (simplified)" << std::endl;
    }
    
    // ★【新增】★ 性能监控循环
    void performance_monitoring_loop() {
        while (running_) {
            auto stats = get_system_stats();
            auto heartbeat = ipc_->get_heartbeat_status();
            
            // 每30秒输出一次统计信息
            static int counter = 0;
            if (++counter % 30 == 0) {
                auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - start_time_).count();
                
                std::cout << "[Stats] 📊 Uptime: " << uptime << "s"
                          << ", Memory: " << stats.memory_usage_percent << "%"
                          << ", Packets: " << sniffer_->get_packets_captured()
                          << ", Heartbeat: " << (heartbeat.is_healthy ? "✅" : "❌")
                          << std::endl;
            }
            
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    
    // ★【新增】★ 打印系统信息
    void print_system_info() {
        auto cpu_info = CPUAffinityManager::get_cpu_info();
        auto stats = get_system_stats();
        
        std::cout << "\n[System Info] 💻 " << get_system_info() << std::endl;
        std::cout << "[System Info] 🧮 CPU Cores: " << cpu_info.total_cores 
                  << " (Physical: " << cpu_info.physical_cores << ")" << std::endl;
        std::cout << "[System Info] 🧠 Memory: " 
                  << (stats.memory_total_bytes / 1024 / 1024) << " MB total" << std::endl;
        std::cout << "[System Info] 🌐 Interface: " << interface_ << std::endl;
        std::cout << std::endl;
    }
};

// 全局对象用于信号处理
static ARPSpooferCore* g_core = nullptr;

void signal_handler(int signum) {
    std::cout << "\n[C++ Core] Received signal " << signum << ", shutting down..." << std::endl;
    if (g_core) {
        g_core->stop();
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>" << std::endl;
        return 1;
    }
    
    std::string interface = argv[1];
    
    // 设置信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // 创建核心对象
    ARPSpooferCore core(interface);
    g_core = &core;
    
    if (!core.initialize()) {
        return 1;
    }
    
    core.run();
    return 0;
}
