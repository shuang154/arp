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

class ARPSpooferCore {
private:
    std::unique_ptr<PacketSniffer> sniffer_;
    std::unique_ptr<ARPSpoofer> spoofer_;
    std::unique_ptr<IPCManager> ipc_;
    volatile bool running_;
    std::string interface_;

public:
    ARPSpooferCore(const std::string& iface) 
        : interface_(iface), running_(true) {
        
        // 初始化IPC管理器
        ipc_ = std::make_unique<IPCManager>();
        
        // 初始化ARP欺骗器
        spoofer_ = std::make_unique<ARPSpoofer>(interface_);
        
        // 初始化数据包嗅探器
        sniffer_ = std::make_unique<PacketSniffer>(interface_);
    }
    
    bool initialize() {
        std::cout << "[C++ Core] Initializing ARP Spoofer Core..." << std::endl;
        
        if (!check_root_privileges()) {
            std::cerr << "[ERROR] This program requires root privileges!" << std::endl;
            return false;
        }
        
        if (!ipc_->initialize("tcp://127.0.0.1:5555", "tcp://127.0.0.1:5556")) {
            std::cerr << "[ERROR] Failed to initialize IPC!" << std::endl;
            return false;
        }
        
        if (!sniffer_->initialize("tcp://127.0.0.1:5555", "tcp://127.0.0.1:5556")) {
            std::cerr << "[ERROR] Failed to initialize packet sniffer!" << std::endl;
            return false;
        }
        
        if (!spoofer_->initialize()) {
            std::cerr << "[ERROR] Failed to initialize ARP spoofer!" << std::endl;
            return false;
        }
        
        std::cout << "[C++ Core] All modules initialized successfully" << std::endl;
        return true;
    }
    
    void run() {
        std::cout << "[C++ Core] Starting main loop..." << std::endl;
        
        // 启动嗅探线程
        std::thread sniffer_thread([this]() {
            bind_to_cpu(2); // 绑定到CPU核心2
            sniffer_->start_capture();
        });
        
        // 启动IPC命令处理循环
        std::thread ipc_thread([this]() {
            bind_to_cpu(3); // 绑定到CPU核心3
            while (running_) {
                std::string command;
                if (ipc_->receive_command(command)) {
                    // 简单输出接收到的命令
                    std::cout << "[IPC] Received command: " << command << std::endl;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        });
        
        // 主线程等待信号
        while (running_) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        // 清理
        sniffer_->stop_capture();
        if (sniffer_thread.joinable()) sniffer_thread.join();
        if (ipc_thread.joinable()) ipc_thread.join();
        
        std::cout << "[C++ Core] Shutdown complete" << std::endl;
    }
    
    void stop() {
        running_ = false;
    }

private:
    void handle_command(const std::string& cmd) {
        // 简单的命令处理，可以根据需要扩展
        std::cout << "[Main] Processing command: " << cmd << std::endl;
        
        // 这里可以添加具体的命令解析和处理逻辑
        // 例如解析 JSON 命令并调用相应的 spoofer 方法
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
