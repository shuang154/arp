#ifndef OBJECT_POOL_H
#define OBJECT_POOL_H

#include <queue>
#include <mutex>
#include <memory>
#include <vector>
#include <functional>

/**
 * 高性能对象池模板类
 * 解决频繁内存分配/释放导致的性能问题和内存碎片
 */
template<typename T>
class ObjectPool {
private:
    std::vector<T*> pool_;
    mutable std::mutex pool_mutex_; // ★【修复】★ 声明为mutable，允许在const函数中加锁
    size_t initial_size_;
    size_t max_size_;
    
    // 统计信息
    std::atomic<uint64_t> objects_created_;
    std::atomic<uint64_t> objects_reused_;
    std::atomic<uint64_t> pool_hits_;
    std::atomic<uint64_t> pool_misses_;

public:
    /**
     * 构造函数
     * @param factory 对象创建工厂函数
     * @param initial_size 初始池大小
     * @param max_size 最大池大小
     */
    ObjectPool(std::function<std::unique_ptr<T>()> factory, 
               size_t initial_size = 100, 
               size_t max_size = 1000)
        : factory_(factory), initial_size_(initial_size), max_size_(max_size),
          objects_created_(0), objects_reused_(0), pool_hits_(0), pool_misses_(0) {
        
        // 预分配对象到池中
        std::lock_guard<std::mutex> lock(pool_mutex_);
        for (size_t i = 0; i < initial_size_; ++i) {
            pool_.push_back(new T());
            objects_created_++;
        }
    }
    
    /**
     * 从池中获取对象
     * 如果池为空，则创建新对象
     */
    std::unique_ptr<T> acquire() {
        std::lock_guard<std::mutex> lock(pool_mutex_);
        
        if (!pool_.empty()) {
            auto obj = pool_.back();
            pool_.pop_back();
            pool_hits_++;
            objects_reused_++;
            return std::unique_ptr<T>(obj);
        }
        
        // 池为空，创建新对象
        pool_misses_++;
        objects_created_++;
        return factory_();
    }
    
    /**
     * 将对象归还到池中
     * 如果池已满，则销毁对象
     */
    void release(std::unique_ptr<T> obj) {
        if (!obj) return;
        
        std::lock_guard<std::mutex> lock(pool_mutex_);
        
        if (pool_.size() < max_size_) {
            // 重置对象状态（如果需要）
            reset_object(obj.get());
            pool_.push_back(obj.release());
        }
        // 如果池已满，对象会自动销毁
    }
    
    /**
     * 获取池统计信息
     */
    struct PoolStats {
        size_t current_size;
        size_t max_size;
        uint64_t objects_created;
        uint64_t objects_reused;
        uint64_t pool_hits;
        uint64_t pool_misses;
        double hit_ratio;
    };
    
    PoolStats get_stats() const {
        std::lock_guard<std::mutex> lock(pool_mutex_);
        
        uint64_t total_requests = pool_hits_ + pool_misses_;
        double hit_ratio = total_requests > 0 ? 
            static_cast<double>(pool_hits_) / total_requests : 0.0;
        
        return {
            pool_.size(),
            max_size_,
            objects_created_.load(),
            objects_reused_.load(),
            pool_hits_.load(),
            pool_misses_.load(),
            hit_ratio
        };
    }
    
    /**
     * 清空池
     */
    void clear() {
        std::lock_guard<std::mutex> lock(pool_mutex_);
        for (auto obj : pool_) {
            delete obj;
        }
        pool_.clear();
    }

private:
    /**
     * 重置对象状态（可以被特化）
     */
    void reset_object(T* obj) {
        // 默认实现为空，子类可以重写
        // 例如：重置计数器、清空缓冲区等
    }
};

// 为PacketInfo特化的对象池
#include "ipc_manager.h"

class PacketInfoPool : public ObjectPool<PacketInfo> {
public:
    PacketInfoPool(size_t initial_size, size_t max_size)
        : ObjectPool<PacketInfo>(initial_size, max_size) {}

protected:
    PacketInfo* create_new() override {
        return new PacketInfo();
    }

    void reset_object(PacketInfo* pkt) override {
        if (pkt) {
            pkt->timestamp = 0;
            pkt->src_ip.clear();
            pkt->dst_ip.clear();
            pkt->protocol = 0;
            pkt->length = 0;
            pkt->data.clear();
        }
    }
};

#endif // OBJECT_POOL_H
