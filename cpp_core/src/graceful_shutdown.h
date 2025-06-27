#ifndef GRACEFUL_SHUTDOWN_H
#define GRACEFUL_SHUTDOWN_H

#include <atomic>
#include <chrono>
#include <functional>
#include <vector>
#include <mutex>
#include <memory>
#include <signal.h>

/**
 * 优雅停机管理器
 * 支持信号处理、资源清理和超时强制停机
 */
class GracefulShutdownManager {
public:
    using ShutdownCallback = std::function<void()>;
    using ShutdownPromise = std::function<bool(int timeout_ms)>; // 返回是否成功停机
    
    enum class ShutdownPhase {
        NOT_STARTED = 0,
        SIGNAL_RECEIVED = 1,
        CLEANUP_PHASE_1 = 2,  // 停止接收新请求
        CLEANUP_PHASE_2 = 3,  // 完成正在处理的请求
        CLEANUP_PHASE_3 = 4,  // 释放资源
        COMPLETED = 5,
        FORCED = 6            // 强制退出
    };

private:
    std::atomic<bool> shutdown_requested_;
    std::atomic<ShutdownPhase> current_phase_;
    std::chrono::steady_clock::time_point shutdown_start_time_;
    
    // 分阶段清理回调
    std::vector<ShutdownCallback> phase1_callbacks_;  // 停止接收新请求
    std::vector<ShutdownCallback> phase2_callbacks_;  // 完成处理中的请求
    std::vector<ShutdownPromise> phase2_promises_;   // 异步等待完成的操作
    std::vector<ShutdownCallback> phase3_callbacks_;  // 释放资源
    
    std::mutex callbacks_mutex_;
    
    // 超时设置
    static constexpr int DEFAULT_PHASE_TIMEOUT_MS = 5000;  // 每个阶段5秒超时
    static constexpr int TOTAL_SHUTDOWN_TIMEOUT_MS = 30000; // 总共30秒超时
    
    int phase_timeout_ms_;
    int total_timeout_ms_;

public:
    GracefulShutdownManager(int phase_timeout_ms = DEFAULT_PHASE_TIMEOUT_MS,
                          int total_timeout_ms = TOTAL_SHUTDOWN_TIMEOUT_MS);
    ~GracefulShutdownManager();
    
    // 启动信号监听
    void setup_signal_handlers();
    
    // 注册清理回调
    void register_phase1_callback(ShutdownCallback callback);  // 停止新请求
    void register_phase2_callback(ShutdownCallback callback);  // 完成现有请求
    void register_phase2_promise(ShutdownPromise promise);     // 异步等待
    void register_phase3_callback(ShutdownCallback callback);  // 资源清理
    
    // 检查停机状态
    bool is_shutdown_requested() const { return shutdown_requested_.load(); }
    ShutdownPhase get_current_phase() const { return current_phase_.load(); }
    bool should_accept_new_requests() const;
    
    // 手动触发停机
    void request_shutdown();
    
    // 执行停机流程
    void execute_shutdown();
    
    // 等待停机完成
    bool wait_for_shutdown(int timeout_ms = -1);
    
    // 获取停机统计信息
    struct ShutdownStats {
        bool completed_gracefully;
        std::chrono::milliseconds total_time;
        ShutdownPhase final_phase;
        bool forced_shutdown;
    };
    
    ShutdownStats get_shutdown_stats() const;

private:
    static void signal_handler(int signum);
    static GracefulShutdownManager* instance_;
    
    void execute_phase1();
    void execute_phase2();
    void execute_phase3();
    
    bool wait_for_phase2_completion();
};

// 全局实例访问器
GracefulShutdownManager* get_shutdown_manager();
void initialize_shutdown_manager();

#endif // GRACEFUL_SHUTDOWN_H
