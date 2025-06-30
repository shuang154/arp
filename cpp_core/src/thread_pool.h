#pragma once

#include <thread>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <functional>
#include <future>

/**
 * 高性能线程池 - 消除锁竞争，优化IP攻击分配
 * 每个线程专门负责一组目标IP，减少线程间竞争
 */
class HighPerformanceThreadPool {
public:
    using Task = std::function<void()>;
    using IPTask = std::function<void(const std::string&)>;

private:
    std::vector<std::thread> workers_;
    std::vector<std::queue<Task>> thread_queues_;  // 每个线程一个队列，减少锁竞争
    std::vector<std::mutex> queue_mutexes_;        // 每个队列一个锁
    std::vector<std::condition_variable> queue_conditions_;
    
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> tasks_completed_{0};
    std::atomic<uint64_t> tasks_assigned_{0};
    
    // IP分配策略 - 哈希到特定线程
    std::hash<std::string> ip_hasher_;
    size_t num_threads_;

public:
    explicit HighPerformanceThreadPool(size_t num_threads = std::thread::hardware_concurrency());
    ~HighPerformanceThreadPool();
    
    void start();
    void stop();
    
    // 分配任务到特定线程（基于IP哈希）
    bool assign_ip_task(const std::string& target_ip, IPTask task);
    
    // 通用任务分配（轮询）
    bool assign_task(Task task);
    
    // 获取统计信息
    size_t get_thread_count() const { return num_threads_; }
    uint64_t get_tasks_completed() const { return tasks_completed_; }
    uint64_t get_tasks_assigned() const { return tasks_assigned_; }
    double get_completion_rate() const;
    
    // 获取每个线程的队列长度（负载监控）
    std::vector<size_t> get_queue_sizes() const;

private:
    void worker_thread(size_t thread_id);
    size_t hash_ip_to_thread(const std::string& ip) const;
};
