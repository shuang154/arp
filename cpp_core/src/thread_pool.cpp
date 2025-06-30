#include "thread_pool.h"
#include <iostream>
#include <iomanip>

HighPerformanceThreadPool::HighPerformanceThreadPool(size_t num_threads) 
    : num_threads_(num_threads) {
    
    // 为每个线程创建独立的队列和同步对象
    thread_queues_.resize(num_threads_);
    queue_mutexes_.resize(num_threads_);
    queue_conditions_.resize(num_threads_);
    
    std::cout << "🚀 创建高性能线程池，线程数: " << num_threads_ << std::endl;
}

HighPerformanceThreadPool::~HighPerformanceThreadPool() {
    stop();
}

void HighPerformanceThreadPool::start() {
    if (running_.load()) {
        return;
    }
    
    running_.store(true);
    workers_.reserve(num_threads_);
    
    for (size_t i = 0; i < num_threads_; ++i) {
        workers_.emplace_back(&HighPerformanceThreadPool::worker_thread, this, i);
    }
    
    std::cout << "✅ 线程池已启动，所有 " << num_threads_ << " 个工作线程运行中" << std::endl;
}

void HighPerformanceThreadPool::stop() {
    if (!running_.load()) {
        return;
    }
    
    std::cout << "🛑 停止线程池..." << std::endl;
    running_.store(false);
    
    // 通知所有线程停止
    for (size_t i = 0; i < num_threads_; ++i) {
        queue_conditions_[i].notify_all();
    }
    
    // 等待所有线程结束
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    
    workers_.clear();
    
    std::cout << "✅ 线程池已停止" << std::endl;
    std::cout << "📊 统计: 总任务=" << tasks_assigned_.load() 
              << ", 已完成=" << tasks_completed_.load() 
              << ", 完成率=" << std::fixed << std::setprecision(1) 
              << get_completion_rate() << "%" << std::endl;
}

bool HighPerformanceThreadPool::assign_ip_task(const std::string& target_ip, IPTask task) {
    if (!running_.load()) {
        return false;
    }
    
    // 🔧 关键优化：根据IP哈希分配到特定线程，同一IP总是在同一线程处理
    size_t thread_id = hash_ip_to_thread(target_ip);
    
    {
        std::lock_guard<std::mutex> lock(queue_mutexes_[thread_id]);
        thread_queues_[thread_id].emplace([task, target_ip]() {
            task(target_ip);
        });
    }
    
    queue_conditions_[thread_id].notify_one();
    tasks_assigned_.fetch_add(1);
    
    return true;
}

bool HighPerformanceThreadPool::assign_task(Task task) {
    if (!running_.load()) {
        return false;
    }
    
    // 轮询分配到负载最少的线程
    size_t min_queue_size = SIZE_MAX;
    size_t best_thread = 0;
    
    for (size_t i = 0; i < num_threads_; ++i) {
        std::lock_guard<std::mutex> lock(queue_mutexes_[i]);
        if (thread_queues_[i].size() < min_queue_size) {
            min_queue_size = thread_queues_[i].size();
            best_thread = i;
        }
    }
    
    {
        std::lock_guard<std::mutex> lock(queue_mutexes_[best_thread]);
        thread_queues_[best_thread].emplace(std::move(task));
    }
    
    queue_conditions_[best_thread].notify_one();
    tasks_assigned_.fetch_add(1);
    
    return true;
}

double HighPerformanceThreadPool::get_completion_rate() const {
    uint64_t assigned = tasks_assigned_.load();
    uint64_t completed = tasks_completed_.load();
    
    if (assigned == 0) return 100.0;
    return (static_cast<double>(completed) / assigned) * 100.0;
}

std::vector<size_t> HighPerformanceThreadPool::get_queue_sizes() const {
    std::vector<size_t> sizes;
    sizes.reserve(num_threads_);
    
    for (size_t i = 0; i < num_threads_; ++i) {
        std::lock_guard<std::mutex> lock(queue_mutexes_[i]);
        sizes.push_back(thread_queues_[i].size());
    }
    
    return sizes;
}

void HighPerformanceThreadPool::worker_thread(size_t thread_id) {
    std::cout << "🎯 工作线程 " << thread_id << " 已启动" << std::endl;
    
    while (running_.load()) {
        Task task;
        bool has_task = false;
        
        {
            std::unique_lock<std::mutex> lock(queue_mutexes_[thread_id]);
            queue_conditions_[thread_id].wait(lock, [this, thread_id] {
                return !thread_queues_[thread_id].empty() || !running_.load();
            });
            
            if (!thread_queues_[thread_id].empty()) {
                task = std::move(thread_queues_[thread_id].front());
                thread_queues_[thread_id].pop();
                has_task = true;
            }
        }
        
        if (has_task) {
            try {
                task();
                tasks_completed_.fetch_add(1);
            } catch (const std::exception& e) {
                std::cerr << "❌ 线程 " << thread_id << " 任务执行异常: " << e.what() << std::endl;
            }
        }
    }
    
    std::cout << "🛑 工作线程 " << thread_id << " 已停止" << std::endl;
}

size_t HighPerformanceThreadPool::hash_ip_to_thread(const std::string& ip) const {
    // 🔧 使用IP地址的哈希值分配线程，确保同一IP总是在同一线程处理
    // 这样可以避免对同一目标的并发攻击，提高效率
    return ip_hasher_(ip) % num_threads_;
}
