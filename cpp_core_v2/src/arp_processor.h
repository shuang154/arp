#pragma once

#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include <atomic>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#include <chrono>
#include <queue>
#include <functional>

// 前向声明
struct PacketData;
struct AttackDecision;
struct Statistics;
struct Config;

/**
 * 高性能ARP攻击处理器
 * 负责数据包捕获、分析、决策和攻击执行
 * 完全替代Python的核心逻辑，解决GIL限制和锁竞争
 */
class ARPProcessor {
public:
    explicit ARPProcessor(const Config& config);
    ~ARPProcessor();

    // 初始化和控制
    bool initialize();
    void start();
    void stop();
    bool is_running() const;

    // Python接口
    Statistics get_statistics() const;
    std::vector<std::string> get_active_attacks() const;
    void update_configuration(const Config& config);

private:
    // 核心处理线程
    void packet_capture_thread();
    void packet_processor_thread(int thread_id);
    void attack_executor_thread();
    void statistics_collector_thread();

    // 数据包处理
    bool capture_packet(PacketData& packet);
    bool analyze_packet(const PacketData& packet, AttackDecision& decision);
    bool execute_attack(const AttackDecision& decision);

    // 状态管理 (原子性操作)
    bool atomic_try_start_attack(const std::string& target_ip);
    void end_attack_session(const std::string& target_ip);
    bool is_target_available(const std::string& target_ip) const;

    // 配置和状态
    Config config_;
    std::atomic<bool> running_{false};
    std::atomic<bool> initialized_{false};

    // 线程管理
    std::vector<std::thread> processor_threads_;
    std::thread capture_thread_;
    std::thread executor_thread_;
    std::thread stats_thread_;

    // 高性能数据结构
    struct StateManager;
    std::unique_ptr<StateManager> state_manager_;

    // 统计信息
    mutable std::shared_mutex stats_mutex_;
    struct {
        std::atomic<uint64_t> packets_captured{0};
        std::atomic<uint64_t> packets_processed{0};
        std::atomic<uint64_t> attacks_launched{0};
        std::atomic<uint64_t> attacks_successful{0};
        std::chrono::steady_clock::time_point start_time;
    } statistics_;
};

/**
 * 高性能状态管理器
 * 使用原子操作和读写锁优化并发性能
 */
class ARPProcessor::StateManager {
public:
    StateManager();
    ~StateManager();

    // 原子性攻击决策
    struct AttackResult {
        bool should_attack;
        std::string reason;
        uint64_t session_id;
    };

    AttackResult atomic_try_start_attack(const std::string& target_ip);
    void end_attack_session(const std::string& target_ip);
    bool is_target_available(const std::string& target_ip) const;

    // 缓存管理
    void update_arp_cache(const std::string& ip, const std::string& mac);
    std::string get_cached_mac(const std::string& ip) const;

    // 统计信息
    struct CacheStats {
        uint64_t total_entries;
        uint64_t cache_hits;
        uint64_t cache_misses;
        double hit_rate;
    };
    CacheStats get_cache_statistics() const;

private:
    // 高性能缓存结构
    struct CacheEntry {
        std::string value;
        std::chrono::steady_clock::time_point timestamp;
    };

    struct AttackSession {
        std::chrono::steady_clock::time_point start_time;
        int duration_seconds;
        bool is_active;
    };

    // 读写锁优化并发
    mutable std::shared_mutex arp_cache_mutex_;
    mutable std::shared_mutex attack_state_mutex_;
    mutable std::shared_mutex stats_mutex_;

    // 高性能缓存
    std::unordered_map<std::string, CacheEntry> arp_cache_;
    std::unordered_map<std::string, AttackSession> active_attacks_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> successful_attacks_;

    // 原子性统计
    mutable std::atomic<uint64_t> cache_hits_{0};
    mutable std::atomic<uint64_t> cache_misses_{0};

    // 配置
    int arp_cache_ttl_seconds_{1800};
    int attack_cooldown_seconds_{3600};
    int active_attack_ttl_seconds_{300};

    // 定时清理
    void cleanup_expired_entries();
    std::thread cleanup_thread_;
    mutable std::condition_variable cleanup_cv_;
    mutable std::mutex cleanup_mutex_;
    std::atomic<bool> cleanup_running_{false};
};

/**
 * 数据结构定义
 */
struct PacketData {
    std::string raw_data;
    std::string source_ip;
    std::string dest_ip;
    std::string source_mac;
    std::string dest_mac;
    std::string packet_type;
    std::unordered_map<std::string, std::string> metadata;
    std::chrono::steady_clock::time_point timestamp;
};

struct AttackDecision {
    bool should_attack;
    std::string target_ip;
    std::string gateway_ip;
    std::string target_mac;
    std::string gateway_mac;
    int duration;
    std::string attack_type;
    std::string reason;
    uint64_t session_id;
};

struct Statistics {
    uint64_t packets_captured;
    uint64_t packets_processed;
    uint64_t attacks_launched;
    uint64_t attacks_successful;
    uint64_t cache_hits;
    uint64_t cache_misses;
    double processing_rate;
    double hit_rate;
    int active_attacks_count;
    std::chrono::seconds uptime;
};

struct Config {
    // 性能配置
    int max_worker_threads = 8;
    int packet_batch_size = 15;
    double packet_batch_timeout = 0.08;
    
    // 网络配置
    std::string interface = "wlan0";
    std::string gateway_ip = "10.17.0.1";
    std::vector<int> target_ports = {80, 443, 8080, 801};
    
    // 攻击配置
    int attack_timeout = 45;
    int max_concurrent_attacks = 12;
    int cooldown_time = 3600;
    
    // 缓存配置
    int arp_cache_ttl = 1800;
    int attack_cache_ttl = 3600;
    int target_info_ttl = 7200;
    
    // IPC配置
    std::string packet_ipc_address = "ipc:///tmp/arp_spoofer_packets.ipc";
    std::string command_ipc_address = "ipc:///tmp/arp_spoofer_commands.ipc";
};
