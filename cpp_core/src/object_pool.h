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
    std::queue<std::unique_ptr<T>> pool_;
    std::mutex pool_mutex_;
    std::function<std::unique_ptr<T>()> factory_;
    size_t max_size_;
    size_t initial_size_;
    
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
            pool_.push(factory_());
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
            auto obj = std::move(pool_.front());
            pool_.pop();
            pool_hits_++;
            objects_reused_++;
            return obj;
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
            pool_.push(std::move(obj));
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
        while (!pool_.empty()) {
            pool_.pop();
        }
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
    PacketInfoPool(size_t initial_size = 1000, size_t max_size = 5000)
        : ObjectPool<PacketInfo>(
            []() { return std::make_unique<PacketInfo>(); },
            initial_size, 
            max_size
        ) {}

private:
    void reset_object(PacketInfo* pkt) {
        // 重置PacketInfo对象的状态
        pkt->type = PacketType::UNKNOWN;
        pkt->src_ip.clear();
        pkt->dst_ip.clear();
        pkt->src_port = 0;
        pkt->dst_port = 0;
        pkt->arp_opcode = 0;
        memset(pkt->src_mac, 0, 6);
        memset(pkt->dst_mac, 0, 6);
        pkt->length = 0;
        memset(pkt->payload, 0, MAX_PAYLOAD_SIZE);
        pkt->payload_length = 0;
        pkt->timestamp = {0, 0};
    }
};

#endif // OBJECT_POOL_H
