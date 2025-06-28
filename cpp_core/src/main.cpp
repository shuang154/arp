#include <iostream>
#include <signal.h>
#include <unistd.h>
#include <thread>
#include <memory>
#include <chrono>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <vector>
#include <iomanip>
#include "packet_sniffer.h"
#include "arp_spoofer.h"
#include "ipc_manager.h"
#include "utils.h"
// #include "graceful_shutdown.h"  // ★【临时注释】★ 未完整实现
#include "config_manager.h"
#include "object_pool.h"

// ★【新增】★ 性能统计结构
struct PerformanceStats {
    std::atomic<uint64_t> packets_processed{0};
    std::atomic<uint64_t> packets_dropped{0};
    std::atomic<uint64_t> commands_queued{0};
    std::atomic<uint64_t> commands_processed{0};
    std::atomic<uint64_t> heartbeat_sent{0};
    std::atomic<uint64_t> heartbeat_received{0};
    std::atomic<double> processing_rate{0.0};
    std::atomic<size_t> queue_depth{0};
    std::chrono::steady_clock::time_point last_update;
    
    PerformanceStats() : last_update(std::chrono::steady_clock::now()) {}
};

// ★【新增】★ 批量命令结构
struct BatchCommand {
    IPCCommand command;
    std::chrono::steady_clock::time_point timestamp;
    
    BatchCommand(const IPCCommand& cmd) 
        : command(cmd), timestamp(std::chrono::steady_clock::now()) {}
};

class ARPSpooferCore {
private:
    std::unique_ptr<PacketSniffer> sniffer_;
    std::unique_ptr<ARPSpoofer> spoofer_;
    std::unique_ptr<IPCManager> ipc_;
    std::unique_ptr<ConfigManager> config_;
    // std::unique_ptr<GracefulShutdownManager> shutdown_manager_;  // ★【临时注释】★ 未完整实现
    
    std::atomic<bool> running_;
    std::string interface_;
    
    // ★【新增】★ 批量命令处理
    std::queue<BatchCommand> command_queue_;
    std::mutex command_queue_mutex_;
    std::condition_variable command_queue_cv_;
    std::thread command_processor_thread_;
    std::atomic<bool> command_processor_running_{false};
    
    // ★【新增】★ 独立心跳通道
    std::unique_ptr<IPCManager> heartbeat_ipc_;
    std::thread dedicated_heartbeat_thread_;
    std::atomic<bool> heartbeat_running_{false};
    
    // ★【新增】★ 性能统计
    PerformanceStats perf_stats_;
    std::mutex stats_mutex_;
    
    // ★【增强】★ 性能监控
    std::thread monitoring_thread_;
    std::chrono::steady_clock::time_point start_time_;
    
    // ★【新增】★ 负载控制
    std::atomic<bool> system_overloaded_{false};
    static constexpr size_t MAX_QUEUE_DEPTH = 1000;
    static constexpr size_t OVERLOAD_THRESHOLD = 800;

public:
    ARPSpooferCore(const std::string& iface) 
        : interface_(iface), running_(true) {
        
        // 初始化配置管理器
        config_ = std::make_unique<ConfigManager>("../config/config.yaml");
        // shutdown_manager_ = std::make_unique<GracefulShutdownManager>();  // ★【临时注释】★ 未完整实现
        
        // 初始化IPC管理器
        ipc_ = std::make_unique<IPCManager>();
        
        // ★【新增】★ 初始化独立心跳IPC
        heartbeat_ipc_ = std::make_unique<IPCManager>();
        
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
        
        // ★【新增】★ 初始化独立心跳IPC
        if (!heartbeat_ipc_->initialize()) {
            std::cerr << "[ERROR] Failed to initialize heartbeat IPC!" << std::endl;
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
        
        // ★【新增】★ 启动命令处理线程
        start_command_processor();
        
        // ★【新增】★ 启动独立心跳线程
        start_dedicated_heartbeat();
        
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
                    // ★【修改】★ 使用批量命令处理而不是直接处理
                    queue_command(*command);
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
        
        // ★【强化关闭顺序】★ 按正确顺序关闭各个组件
        
        // ★【新增】★ 停止批量命令处理线程
        stop_command_processor();
        
        // ★【新增】★ 停止独立心跳线程
        stop_dedicated_heartbeat();
        
        // 1. 首先停止ARP欺骗器，这会清理所有活跃的攻击会话
        if (spoofer_) {
            std::cout << "[C++ Core] Shutting down ARP spoofer..." << std::endl;
            spoofer_->shutdown();
        }
        
        // 2. 停止数据包嗅探
        if (sniffer_) {
            std::cout << "[C++ Core] Stopping packet sniffer..." << std::endl;
            // ★【新增】★ 打印对象池统计信息
            sniffer_->print_pool_stats();
            sniffer_->stop();
        }
        
        // 3. 等待嗅探线程退出
        if (sniffer_thread.joinable()) {
            std::cout << "[C++ Core] Waiting for sniffer thread..." << std::endl;
            sniffer_thread.join();
            std::cout << "[C++ Core] Sniffer thread joined" << std::endl;
        }
        
        // 4. 等待IPC线程退出
        if (ipc_thread.joinable()) {
            std::cout << "[C++ Core] Waiting for IPC thread..." << std::endl;
            ipc_thread.join();
            std::cout << "[C++ Core] IPC thread joined" << std::endl;
        }
        
        // 5. 等待监控线程退出
        if (monitoring_thread_.joinable()) {
            std::cout << "[C++ Core] Waiting for monitoring thread..." << std::endl;
            monitoring_thread_.join();
            std::cout << "[C++ Core] Monitoring thread joined" << std::endl;
        }
        
        // 6. 停止心跳
        if (ipc_) {
            std::cout << "[C++ Core] Stopping heartbeat..." << std::endl;
            ipc_->stop_heartbeat();
        }
        
        // 7. 清理独立心跳IPC
        if (heartbeat_ipc_) {
            std::cout << "[C++ Core] Cleaning up heartbeat IPC..." << std::endl;
            heartbeat_ipc_.reset();
        }
        
        std::cout << "[C++ Core] ✅ Shutdown complete" << std::endl;
    }
    
    void stop() {
        running_ = false;
    }

private:
    void handle_command(const IPCCommand& cmd) {
        // 更新统计信息
        perf_stats_.packets_processed++;
        
        switch (cmd.type) {
            case CommandType::START_SPOOF:
                std::cout << "[C++ Core] Starting " << cmd.attack_type << " spoofing for " << cmd.target_ip;
                if (cmd.duration > 0) {
                    std::cout << " (duration: " << cmd.duration << "s)";
                }
                std::cout << std::endl;
                
                spoofer_->start_spoofing(cmd.target_ip, cmd.gateway_ip, 
                                       cmd.target_mac, cmd.gateway_mac,
                                       cmd.duration, cmd.attack_type);
                break;
            case CommandType::STOP_SPOOF:
                std::cout << "[C++ Core] Stopping spoofing for " << cmd.target_ip << std::endl;
                spoofer_->stop_spoofing(cmd.target_ip);
                break;
            case CommandType::RESTORE_ARP:
                std::cout << "[C++ Core] Restoring ARP for " << cmd.target_ip << std::endl;
                spoofer_->restore_arp(cmd.target_ip, cmd.gateway_ip,
                                    cmd.target_mac, cmd.gateway_mac);
                break;
            case CommandType::PONG:
                // 心跳响应已在IPC管理器中处理
                perf_stats_.heartbeat_received++;
                break;
            case CommandType::PING:
                // 收到心跳请求，发送响应
                if (ipc_) {
                    IPCCommand pong_cmd;
                    pong_cmd.type = CommandType::PONG;
                    ipc_->send_command(pong_cmd);
                    perf_stats_.heartbeat_sent++;
                }
                break;
            case CommandType::SHUTDOWN:
                std::cout << "[C++ Core] Received shutdown command from Python" << std::endl;
                stop();
                break;
            default:
                std::cerr << "[WARNING] Unknown command type: " << static_cast<int>(cmd.type) << std::endl;
                perf_stats_.packets_dropped++;
        }
    }
    
    // ★【临时注释】★ 优雅停机功能暂时不可用
    void setup_graceful_shutdown() {
        // 简化版本 - 仅设置信号处理
        std::cout << "[Setup] Graceful shutdown configured (simplified)" << std::endl;
    }
    
    // ★【新增】★ 批量命令处理方法
    void queue_command(const IPCCommand& cmd) {
        std::unique_lock<std::mutex> lock(command_queue_mutex_);
        
        // 负载控制：检查队列深度
        if (command_queue_.size() >= MAX_QUEUE_DEPTH) {
            system_overloaded_ = true;
            perf_stats_.commands_dropped++;
            std::cerr << "[WARNING] Command queue full, dropping command" << std::endl;
            return;
        }
        
        if (command_queue_.size() < OVERLOAD_THRESHOLD) {
            system_overloaded_ = false;
        }
        
        command_queue_.emplace(cmd);
        perf_stats_.commands_queued++;
        perf_stats_.queue_depth = command_queue_.size();
        
        command_queue_cv_.notify_one();
    }
    
    void start_command_processor() {
        command_processor_running_ = true;
        command_processor_thread_ = std::thread([this]() {
            std::cout << "[Command Processor] Started batch command processing thread" << std::endl;
            
            while (command_processor_running_) {
                std::unique_lock<std::mutex> lock(command_queue_mutex_);
                
                // 等待命令或超时
                command_queue_cv_.wait_for(lock, std::chrono::milliseconds(100), 
                    [this] { return !command_queue_.empty() || !command_processor_running_; });
                
                if (!command_processor_running_) break;
                
                // 批量处理命令
                std::vector<BatchCommand> batch;
                const size_t BATCH_SIZE = 10;
                
                while (!command_queue_.empty() && batch.size() < BATCH_SIZE) {
                    batch.push_back(command_queue_.front());
                    command_queue_.pop();
                }
                
                perf_stats_.queue_depth = command_queue_.size();
                lock.unlock();
                
                // 处理批次
                for (const auto& batch_cmd : batch) {
                    handle_command(batch_cmd.command);
                    perf_stats_.commands_processed++;
                    
                    // 检查命令是否过期
                    auto age = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - batch_cmd.timestamp);
                    if (age.count() > 5000) { // 5秒超时
                        std::cerr << "[WARNING] Command expired: " << age.count() << "ms old" << std::endl;
                    }
                }
                
                // 避免CPU过载
                if (system_overloaded_) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            }
            
            std::cout << "[Command Processor] Batch command processing thread stopped" << std::endl;
        });
    }
    
    void stop_command_processor() {
        if (command_processor_running_) {
            command_processor_running_ = false;
            command_queue_cv_.notify_all();
            
            if (command_processor_thread_.joinable()) {
                std::cout << "[C++ Core] Waiting for command processor thread..." << std::endl;
                command_processor_thread_.join();
                std::cout << "[C++ Core] Command processor thread joined" << std::endl;
            }
        }
    }
    
    // ★【新增】★ 独立心跳处理方法
    void start_dedicated_heartbeat() {
        heartbeat_running_ = true;
        dedicated_heartbeat_thread_ = std::thread([this]() {
            std::cout << "[Heartbeat] Started dedicated heartbeat thread" << std::endl;
            
            auto last_heartbeat = std::chrono::steady_clock::now();
            const auto HEARTBEAT_INTERVAL = std::chrono::seconds(5);
            const auto HEARTBEAT_TIMEOUT = std::chrono::seconds(15);
            
            while (heartbeat_running_) {
                auto now = std::chrono::steady_clock::now();
                
                // 发送心跳
                if (now - last_heartbeat >= HEARTBEAT_INTERVAL) {
                    if (heartbeat_ipc_) {
                        // 使用独立的心跳IPC发送PING
                        IPCCommand ping_cmd;
                        ping_cmd.type = CommandType::PING;
                        
                        if (heartbeat_ipc_->send_command(ping_cmd)) {
                            perf_stats_.heartbeat_sent++;
                            last_heartbeat = now;
                        } else {
                            std::cerr << "[Heartbeat] Failed to send PING via dedicated channel" << std::endl;
                        }
                    }
                }
                
                // 检查心跳响应
                if (heartbeat_ipc_) {
                    auto response = heartbeat_ipc_->receive_command();
                    if (response && response->type == CommandType::PONG) {
                        perf_stats_.heartbeat_received++;
                    }
                }
                
                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            }
            
            std::cout << "[Heartbeat] Dedicated heartbeat thread stopped" << std::endl;
        });
    }
    
    void stop_dedicated_heartbeat() {
        if (heartbeat_running_) {
            heartbeat_running_ = false;
            
            if (dedicated_heartbeat_thread_.joinable()) {
                std::cout << "[C++ Core] Waiting for dedicated heartbeat thread..." << std::endl;
                dedicated_heartbeat_thread_.join();
                std::cout << "[C++ Core] Dedicated heartbeat thread joined" << std::endl;
            }
        }
    }
    
    // ★【增强】★ 性能监控循环
    void performance_monitoring_loop() {
        std::cout << "[Monitoring] Performance monitoring started" << std::endl;
        
        auto last_stats_time = std::chrono::steady_clock::now();
        uint64_t last_packets = 0;
        uint64_t last_commands = 0;
        
        while (running_) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_stats_time);
            
            if (elapsed.count() >= 10) { // 每10秒更新一次
                // 计算处理速率
                auto current_packets = perf_stats_.packets_processed.load();
                auto current_commands = perf_stats_.commands_processed.load();
                
                double packet_rate = (current_packets - last_packets) / static_cast<double>(elapsed.count());
                double command_rate = (current_commands - last_commands) / static_cast<double>(elapsed.count());
                
                perf_stats_.processing_rate = packet_rate;
                
                // 更新统计
                last_packets = current_packets;
                last_commands = current_commands;
                last_stats_time = now;
                
                // 输出详细统计信息
                std::lock_guard<std::mutex> lock(stats_mutex_);
                auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - start_time_).count();
                
                std::cout << "[Stats] 📊 Performance Report:" << std::endl;
                std::cout << "  Uptime: " << uptime << "s" << std::endl;
                std::cout << "  Packets: " << current_packets << " (rate: " << packet_rate << "/s)" << std::endl;
                std::cout << "  Commands: " << current_commands << " (rate: " << command_rate << "/s)" << std::endl;
                std::cout << "  Queue depth: " << perf_stats_.queue_depth.load() << std::endl;
                std::cout << "  Heartbeat: sent=" << perf_stats_.heartbeat_sent.load() 
                          << " received=" << perf_stats_.heartbeat_received.load() << std::endl;
                std::cout << "  System overloaded: " << (system_overloaded_ ? "YES" : "NO") << std::endl;
                
                // 检查性能警告
                if (perf_stats_.queue_depth.load() > OVERLOAD_THRESHOLD) {
                    std::cout << "  ⚠️  WARNING: High queue depth detected!" << std::endl;
                }
                if (packet_rate > 1000) {
                    std::cout << "  ⚠️  WARNING: High packet processing rate!" << std::endl;
                }
            }
            
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        // 输出最终统计信息
        print_final_stats();
    }
    
    // ★【新增】★ 打印最终统计信息
    void print_final_stats() {
        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - start_time_).count();
        
        std::cout << "\n[Final Stats] 📋 Session Summary:" << std::endl;
        std::cout << "  Total uptime: " << uptime << " seconds" << std::endl;
        std::cout << "  Packets processed: " << perf_stats_.packets_processed.load() << std::endl;
        std::cout << "  Packets dropped: " << perf_stats_.packets_dropped.load() << std::endl;
        std::cout << "  Commands queued: " << perf_stats_.commands_queued.load() << std::endl;
        std::cout << "  Commands processed: " << perf_stats_.commands_processed.load() << std::endl;
        std::cout << "  Heartbeats sent: " << perf_stats_.heartbeat_sent.load() << std::endl;
        std::cout << "  Heartbeats received: " << perf_stats_.heartbeat_received.load() << std::endl;
        
        if (uptime > 0) {
            std::cout << "  Average packet rate: " 
                      << (perf_stats_.packets_processed.load() / uptime) << " packets/sec" << std::endl;
            std::cout << "  Average command rate: " 
                      << (perf_stats_.commands_processed.load() / uptime) << " commands/sec" << std::endl;
        }
        
        // 计算效率指标
        double packet_drop_rate = 0.0;
        if (perf_stats_.packets_processed.load() > 0) {
            packet_drop_rate = (double)perf_stats_.packets_dropped.load() / 
                              (perf_stats_.packets_processed.load() + perf_stats_.packets_dropped.load()) * 100.0;
        }
        
        double heartbeat_success_rate = 0.0;
        if (perf_stats_.heartbeat_sent.load() > 0) {
            heartbeat_success_rate = (double)perf_stats_.heartbeat_received.load() / 
                                    perf_stats_.heartbeat_sent.load() * 100.0;
        }
        
        std::cout << "  Packet drop rate: " << std::fixed << std::setprecision(2) 
                  << packet_drop_rate << "%" << std::endl;
        std::cout << "  Heartbeat success rate: " << std::fixed << std::setprecision(2) 
                  << heartbeat_success_rate << "%" << std::endl;
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
