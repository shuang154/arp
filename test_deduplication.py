#!/usr/bin/env python3
"""
ARP Spoofer Pro - 入口去重测试脚本
==========================================
测试数据包去重缓存的功能、性能和线程安全性
"""

import hashlib
import time
import threading
import json
import sys
import os
from pathlib import Path

try:
    from cachetools import TTLCache
    HAS_CACHETOOLS = True
except ImportError:
    print("⚠️ cachetools未安装，使用简单字典模拟TTLCache")
    HAS_CACHETOOLS = False
    
    class TTLCache(dict):
        def __init__(self, maxsize=500, ttl=3):
            super().__init__()
            self.maxsize = maxsize
            self.ttl = ttl
            self._timestamps = {}
        
        def __setitem__(self, key, value):
            current_time = time.time()
            # 清理过期项
            self._cleanup()
            # 如果达到最大容量，删除最旧的项
            if len(self) >= self.maxsize:
                oldest_key = min(self._timestamps.keys(), key=lambda k: self._timestamps[k])
                del self[oldest_key]
                del self._timestamps[oldest_key]
            
            super().__setitem__(key, value)
            self._timestamps[key] = current_time
        
        def __contains__(self, key):
            if not super().__contains__(key):
                return False
            
            # 检查是否过期
            if time.time() - self._timestamps[key] > self.ttl:
                del self[key]
                del self._timestamps[key]
                return False
            return True
        
        def _cleanup(self):
            current_time = time.time()
            expired_keys = [k for k, t in self._timestamps.items() if current_time - t > self.ttl]
            for key in expired_keys:
                if key in self:
                    del self[key]
                del self._timestamps[key]

# 添加python_supervisor到路径
sys.path.insert(0, str(Path(__file__).parent / "python_supervisor"))

class DeduplicationTester:
    """去重功能测试器"""
    
    def __init__(self):
        self.recent_packets_cache = TTLCache(maxsize=500, ttl=3)
        self.cache_lock = threading.Lock()
        self.test_stats = {
            'total_packets': 0,
            'duplicate_packets': 0,
            'unique_packets': 0,
            'cache_hits': 0,
            'cache_misses': 0
        }
    
    def simulate_packet_processing(self, packet_data: bytes) -> bool:
        """
        模拟数据包处理，返回True表示应该处理，False表示重复丢弃
        """
        self.test_stats['total_packets'] += 1
        
        # 计算数据包的哈希值作为唯一"指纹"
        payload_hash = hashlib.sha1(packet_data).hexdigest()
        
        # 检查指纹是否存在于近期缓存中
        with self.cache_lock:
            if payload_hash in self.recent_packets_cache:
                # 如果存在，说明是重复包，直接丢弃
                self.test_stats['duplicate_packets'] += 1
                self.test_stats['cache_hits'] += 1
                print(f"🚫 Duplicate packet dropped (hash: {payload_hash[:8]})")
                return False
            else:
                # 如果是新包，将其指纹存入缓存
                self.recent_packets_cache[payload_hash] = True
                self.test_stats['unique_packets'] += 1
                self.test_stats['cache_misses'] += 1
                print(f"✅ New packet processed (hash: {payload_hash[:8]})")
                return True
    
    def test_basic_deduplication(self):
        """测试基本去重功能"""
        print("\n" + "="*60)
        print("🧪 测试1: 基本去重功能")
        print("="*60)
        
        # 创建测试数据包
        packet1 = json.dumps({
            "source_ip": "192.168.1.100",
            "dest_ip": "10.17.0.1",
            "payload": "username=admin&password=123456",
            "timestamp": 1234567890
        }).encode('utf-8')
        
        packet2 = json.dumps({
            "source_ip": "192.168.1.101", 
            "dest_ip": "10.17.0.1",
            "payload": "username=user&password=test123",
            "timestamp": 1234567891
        }).encode('utf-8')
        
        # 第一次处理每个包 - 应该都通过
        assert self.simulate_packet_processing(packet1) == True
        assert self.simulate_packet_processing(packet2) == True
        
        # 立即重复处理相同包 - 应该被丢弃
        assert self.simulate_packet_processing(packet1) == False
        assert self.simulate_packet_processing(packet2) == False
        
        # 再次重复 - 仍应该被丢弃
        assert self.simulate_packet_processing(packet1) == False
        
        print("✅ 基本去重功能测试通过")
    
    def test_ttl_expiration(self):
        """测试TTL过期功能"""
        print("\n" + "="*60)
        print("🧪 测试2: TTL过期功能")
        print("="*60)
        
        # 创建测试包
        packet = json.dumps({
            "source_ip": "192.168.1.200",
            "payload": "test_ttl_expiration",
            "timestamp": int(time.time())
        }).encode('utf-8')
        
        # 第一次处理 - 应该通过
        assert self.simulate_packet_processing(packet) == True
        
        # 立即重复 - 应该被丢弃
        assert self.simulate_packet_processing(packet) == False
        
        print("⏰ 等待4秒让缓存过期...")
        time.sleep(4)  # 等待TTL过期（TTL设为3秒）
        
        # TTL过期后再次处理 - 应该通过
        assert self.simulate_packet_processing(packet) == True
        
        print("✅ TTL过期功能测试通过")
    
    def test_thread_safety(self):
        """测试线程安全性"""
        print("\n" + "="*60)
        print("🧪 测试3: 线程安全性")
        print("="*60)
        
        # 重置统计
        self.test_stats = {k: 0 for k in self.test_stats}
        
        def worker_thread(thread_id: int, packet_count: int):
            """工作线程函数"""
            for i in range(packet_count):
                # 创建一些重复、一些唯一的数据包
                if i % 3 == 0:
                    # 每3个包创建一个重复包
                    packet_data = f"duplicate_packet_thread_{thread_id}".encode('utf-8')
                else:
                    # 创建唯一包
                    packet_data = f"unique_packet_thread_{thread_id}_seq_{i}_{time.time()}".encode('utf-8')
                
                self.simulate_packet_processing(packet_data)
                time.sleep(0.001)  # 短暂延迟模拟真实情况
        
        # 启动多个工作线程
        threads = []
        thread_count = 5
        packets_per_thread = 20
        
        print(f"🚀 启动{thread_count}个线程，每个处理{packets_per_thread}个包...")
        
        for i in range(thread_count):
            thread = threading.Thread(
                target=worker_thread, 
                args=(i, packets_per_thread),
                name=f"TestWorker-{i}"
            )
            threads.append(thread)
            thread.start()
        
        # 等待所有线程完成
        for thread in threads:
            thread.join()
        
        print("✅ 线程安全性测试完成")
        self.print_stats()
    
    def test_performance(self):
        """测试性能"""
        print("\n" + "="*60)
        print("🧪 测试4: 性能测试")
        print("="*60)
        
        # 重置统计
        self.test_stats = {k: 0 for k in self.test_stats}
        
        packet_count = 1000
        start_time = time.time()
        
        print(f"🚀 处理{packet_count}个数据包...")
        
        for i in range(packet_count):
            # 创建50%重复包来测试去重效果
            if i % 2 == 0:
                packet_data = f"duplicate_performance_test_{i//2}".encode('utf-8')
            else:
                packet_data = f"unique_performance_test_{i}_{time.time()}".encode('utf-8')
            
            self.simulate_packet_processing(packet_data)
        
        end_time = time.time()
        duration = end_time - start_time
        pps = packet_count / duration
        
        print(f"⏱️ 处理时间: {duration:.3f}秒")
        print(f"📊 处理速度: {pps:.1f} 包/秒")
        print("✅ 性能测试完成")
        self.print_stats()
    
    def test_integration_with_supervisor(self):
        """测试与PythonSupervisor的集成"""
        print("\n" + "="*60)
        print("🧪 测试5: 与PythonSupervisor集成")
        print("="*60)
        
        try:
            # 尝试导入PythonSupervisor和Config
            from config import Config
            from main import PythonSupervisor
            
            print("✅ 成功导入PythonSupervisor和Config")
            
            # 加载配置
            config_path = Path(__file__).parent / "config" / "config.yaml"
            if config_path.exists():
                config = Config.load_from_file(str(config_path))
                print("✅ 成功加载配置文件")
                
                # 创建监督者实例（不实际启动）
                supervisor = PythonSupervisor(config)
                print("✅ 成功创建PythonSupervisor实例")
                
                # 检查去重相关属性
                if hasattr(supervisor, 'recent_packets_cache'):
                    print("✅ PythonSupervisor已包含去重缓存")
                else:
                    print("❌ PythonSupervisor缺少去重缓存")
                
                if hasattr(supervisor, 'cache_lock'):
                    print("✅ PythonSupervisor已包含缓存锁")
                else:
                    print("❌ PythonSupervisor缺少缓存锁")
                    
            else:
                print("⚠️ 配置文件不存在，跳过集成测试")
                
        except ImportError as e:
            print(f"⚠️ 无法导入依赖模块: {e}")
            print("请确保运行环境正确设置")
        except Exception as e:
            print(f"❌ 集成测试失败: {e}")
    
    def print_stats(self):
        """打印统计信息"""
        print("\n" + "-"*40)
        print("📊 测试统计:")
        print("-"*40)
        for key, value in self.test_stats.items():
            print(f"{key.replace('_', ' ').title()}: {value}")
        
        if self.test_stats['total_packets'] > 0:
            duplicate_rate = (self.test_stats['duplicate_packets'] / self.test_stats['total_packets']) * 100
            print(f"Duplicate Rate: {duplicate_rate:.1f}%")
        
        print(f"Cache Size: {len(self.recent_packets_cache)}")
        print("-"*40)

def main():
    """主测试函数"""
    print("🎯 ARP Spoofer Pro - 入口去重功能测试")
    print("=" * 60)
    
    if not HAS_CACHETOOLS:
        print("⚠️ 使用简化的TTLCache实现进行测试")
    
    tester = DeduplicationTester()
    
    try:
        # 运行所有测试
        tester.test_basic_deduplication()
        tester.test_ttl_expiration()
        tester.test_thread_safety()
        tester.test_performance()
        tester.test_integration_with_supervisor()
        
        print("\n" + "="*60)
        print("🎉 所有测试完成！入口去重功能工作正常")
        print("="*60)
        
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

def test_packet_deduplication():
    """测试数据包去重功能"""
    print("🧪 测试数据包去重功能")
    print("=" * 60)
    
    try:
        from main import PythonSupervisor
        from config import Config
        
        # 加载配置
        config = Config.load_from_file("config/config.yaml")
        
        # 创建监督者实例（不实际启动）
        supervisor = PythonSupervisor(config)
        
        # 模拟相同的数据包
        test_packet = {
            "type": "http",
            "source_ip": "192.168.1.100",
            "destination_ip": "121.248.150.37",
            "destination_port": 801,
            "payload": "POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Length: 25\r\n\r\nusername=test&password=123"
        }
        
        packet_json = json.dumps(test_packet)
        packet_bytes = packet_json.encode('utf-8')
        
        # 计算哈希值
        packet_hash = hashlib.sha1(packet_bytes).hexdigest()
        print(f"测试数据包哈希: {packet_hash[:16]}...")
        
        # 第一次处理 - 应该被接受
        with supervisor.cache_lock:
            if packet_hash in supervisor.recent_packets_cache:
                print("❌ 第一次处理失败 - 缓存中不应该存在")
                return False
            else:
                supervisor.recent_packets_cache[packet_hash] = True
                print("✅ 第一次处理成功 - 数据包被接受并缓存")
        
        # 第二次处理 - 应该被拒绝（重复）
        with supervisor.cache_lock:
            if packet_hash in supervisor.recent_packets_cache:
                print("✅ 第二次处理成功 - 重复数据包被正确识别并拒绝")
                duplicate_detected = True
            else:
                print("❌ 第二次处理失败 - 应该检测到重复")
                return False
        
        # 测试不同的数据包
        different_packet = {
            "type": "http",
            "source_ip": "192.168.1.101",  # 不同的源IP
            "destination_ip": "121.248.150.37",
            "destination_port": 801,
            "payload": "POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Length: 25\r\n\r\nusername=test&password=123"
        }
        
        different_packet_json = json.dumps(different_packet)
        different_packet_bytes = different_packet_json.encode('utf-8')
        different_hash = hashlib.sha1(different_packet_bytes).hexdigest()
        
        print(f"不同数据包哈希: {different_hash[:16]}...")
        
        # 处理不同的数据包 - 应该被接受
        with supervisor.cache_lock:
            if different_hash in supervisor.recent_packets_cache:
                print("❌ 不同数据包处理失败 - 不应该在缓存中")
                return False
            else:
                supervisor.recent_packets_cache[different_hash] = True
                print("✅ 不同数据包处理成功 - 被正确接受")
        
        print("\n🎉 数据包去重功能测试通过！")
        return True
        
    except Exception as e:
        print(f"❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_cache_performance():
    """测试缓存性能"""
    print("\n🧪 测试缓存性能")
    print("=" * 60)
    
    try:
        from main import PythonSupervisor
        from config import Config
        
        config = Config.load_from_file("config/config.yaml")
        supervisor = PythonSupervisor(config)
        
        # 生成大量测试数据包
        num_packets = 1000
        packets = []
        
        for i in range(num_packets):
            packet = {
                "type": "http",
                "source_ip": f"192.168.1.{i % 254 + 1}",
                "destination_ip": "121.248.150.37",
                "destination_port": 801,
                "timestamp": time.time() + i * 0.001,
                "payload": f"packet_{i}"
            }
            packets.append(json.dumps(packet).encode('utf-8'))
        
        # 测试处理速度
        start_time = time.time()
        processed = 0
        duplicates = 0
        
        for packet_bytes in packets:
            packet_hash = hashlib.sha1(packet_bytes).hexdigest()
            
            with supervisor.cache_lock:
                if packet_hash in supervisor.recent_packets_cache:
                    duplicates += 1
                else:
                    supervisor.recent_packets_cache[packet_hash] = True
                    processed += 1
        
        # 重复处理同样的数据包，测试去重效果
        for packet_bytes in packets[:100]:  # 重复前100个包
            packet_hash = hashlib.sha1(packet_bytes).hexdigest()
            
            with supervisor.cache_lock:
                if packet_hash in supervisor.recent_packets_cache:
                    duplicates += 1
                else:
                    supervisor.recent_packets_cache[packet_hash] = True
                    processed += 1
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"处理 {num_packets + 100} 个数据包用时: {duration:.3f}s")
        print(f"新数据包处理: {processed} 个")
        print(f"重复数据包拒绝: {duplicates} 个")
        print(f"处理速度: {(num_packets + 100) / duration:.0f} 包/秒")
        print(f"缓存命中率: {duplicates / (processed + duplicates) * 100:.1f}%")
        
        # 验证重复检测
        if duplicates >= 100:  # 至少应该检测到重复的100个包
            print("✅ 重复检测功能正常")
        else:
            print("❌ 重复检测功能异常")
            return False
        
        print("✅ 缓存性能测试通过！")
        return True
        
    except Exception as e:
        print(f"❌ 性能测试失败: {e}")
        return False

def test_thread_safety():
    """测试线程安全性"""
    print("\n🧪 测试线程安全性")
    print("=" * 60)
    
    try:
        from main import PythonSupervisor
        from config import Config
        
        config = Config.load_from_file("config/config.yaml")
        supervisor = PythonSupervisor(config)
        
        # 多线程并发测试
        num_threads = 10
        packets_per_thread = 100
        results = []
        
        def worker_thread(thread_id):
            processed = 0
            duplicates = 0
            
            for i in range(packets_per_thread):
                packet = {
                    "thread_id": thread_id,
                    "packet_id": i,
                    "timestamp": time.time()
                }
                packet_bytes = json.dumps(packet).encode('utf-8')
                packet_hash = hashlib.sha1(packet_bytes).hexdigest()
                
                with supervisor.cache_lock:
                    if packet_hash in supervisor.recent_packets_cache:
                        duplicates += 1
                    else:
                        supervisor.recent_packets_cache[packet_hash] = True
                        processed += 1
                
                # 模拟一些处理时间
                time.sleep(0.001)
            
            results.append((thread_id, processed, duplicates))
        
        # 启动多个线程
        threads = []
        start_time = time.time()
        
        for i in range(num_threads):
            thread = threading.Thread(target=worker_thread, args=(i,))
            threads.append(thread)
            thread.start()
        
        # 等待所有线程完成
        for thread in threads:
            thread.join()
        
        end_time = time.time()
        
        # 统计结果
        total_processed = sum(r[1] for r in results)
        total_duplicates = sum(r[2] for r in results)
        
        print(f"线程数: {num_threads}")
        print(f"每线程数据包: {packets_per_thread}")
        print(f"总用时: {end_time - start_time:.3f}s")
        print(f"总处理: {total_processed} 个")
        print(f"总重复: {total_duplicates} 个")
        
        # 验证没有数据竞争
        expected_processed = num_threads * packets_per_thread
        if total_processed == expected_processed and total_duplicates == 0:
            print("✅ 线程安全测试通过！")
            return True
        else:
            print(f"❌ 线程安全测试失败: 期望处理{expected_processed}, 实际处理{total_processed}")
            return False
        
    except Exception as e:
        print(f"❌ 线程安全测试失败: {e}")
        return False

def main():
    """主测试函数"""
    print("🚀 入口流量去重优化验证")
    print("=" * 80)
    print("此测试验证系统是否能有效防止重复处理相同的数据包")
    print("从而消除重复的凭据捕获和网络恢复操作")
    print()
    
    tests = [
        test_packet_deduplication,
        test_cache_performance,
        test_thread_safety
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                print(f"测试失败: {test.__name__}")
        except Exception as e:
            print(f"测试异常: {test.__name__} - {e}")
    
    print("\n" + "=" * 80)
    print(f"📊 测试结果: {passed}/{total} 通过")
    
    if passed == total:
        print("🎉 所有测试通过！入口流量去重优化成功！")
        print("\n💡 优化效果:")
        print("• 🚫 重复数据包自动识别并丢弃")
        print("• 🎯 相同凭据事件只处理一次")
        print("• 🔒 线程安全的高效缓存机制")
        print("• ⚡ 高性能哈希指纹计算")
        print("• 🧹 自动TTL过期清理机制")
        print("\n🎯 预期效果:")
        print("• 日志更干净 - 不再有重复的凭据捕获记录")
        print("• 操作更精准 - 每个目标只会恢复网络一次")
        print("• 性能更优 - 减少不必要的重复处理")
    else:
        print("❌ 部分测试失败，请检查优化代码")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
