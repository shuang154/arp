#!/usr/bin/env python3
"""
ARP Spoofer Python Supervisor v3.0 - C++ Core Integration
==========================================================
职责：
1. 启动和管理C++高性能核心处理器
2. 提供Web API和监控接口
3. 配置管理和日志记录
4. 统计信息收集和展示

核心处理完全由C++负责，解决GIL限制和锁竞争问题
"""

import time
import threading
import logging
import argparse
import signal
import sys
import yaml
from typing import Optional, Dict
from datetime import datetime

# 导入C++核心模块
try:
    import arp_core_cpp
    print("✅ C++ core module loaded successfully")
except ImportError as e:
    print(f"❌ Failed to import C++ core module: {e}")
    print("Please build the C++ module first:")
    print("  cd cpp_core_v2 && mkdir build && cd build")
    print("  cmake .. && make -j4")
    sys.exit(1)

from config import Config

# Web API 可选导入（性能优化：关闭Web功能）
try:
    from web_api import WebAPI
    WEB_API_AVAILABLE = True
except ImportError:
    print("⚠️ Web API module not available (Flask not installed)")
    print("💡 This is expected for performance-optimized deployments")
    WEB_API_AVAILABLE = False
    WebAPI = None

class PythonSupervisor:
    """简化的Python监督者 - 主要负责启动C++核心和提供接口"""
    
    def __init__(self, config: Config):
        self.config = config
        self.running = False
        
        # 首先设置日志
        self._setup_logging()
        
        self.logger.info("🔧 Initializing PythonSupervisor...")
        
        # C++核心处理器
        self.cpp_processor = None
        
        # Web API (如果启用且可用)
        if config.enable_web_api and WEB_API_AVAILABLE:
            self.web_api = WebAPI(self, config)
        else:
            self.web_api = None
            if config.enable_web_api and not WEB_API_AVAILABLE:
                self.logger.warning("⚠️ Web API 已配置但不可用 (Flask未安装)")
            else:
                self.logger.info("💡 Web API 已禁用 - 专注核心性能")
        
        # 监控线程
        self.monitor_thread = None
        
        # 统计信息
        self.stats = {
            'start_time': time.time(),
            'python_uptime': 0,
            'last_cpp_stats': None
        }
        
    def _setup_logging(self):
        """设置日志系统"""
        logging.basicConfig(
            level=getattr(logging, self.config.log_level.upper()),
            format='[%(asctime)s] [%(threadName)-20s] [%(levelname)-8s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            handlers=[
                logging.FileHandler(self.config.log_file, mode='a'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        self.logger = logging.getLogger(__name__)
        
    def initialize(self) -> bool:
        """初始化监督者和C++核心"""
        try:
            self.logger.info("🚀 Initializing Python Supervisor v3.0 with C++ Core...")
            
            # 🔧 转换Python配置为C++配置
            cpp_config = self._convert_config_to_cpp()
            
            # 🔧 创建C++处理器
            self.cpp_processor = arp_core_cpp.ARPProcessor(cpp_config)
            
            # 🔧 初始化C++处理器
            if not self.cpp_processor.initialize():
                self.logger.error("❌ Failed to initialize C++ processor")
                return False
                
            # 启动Web API（如果启用且可用）
            if self.config.enable_web_api and self.web_api:
                self.web_api.start(self.config.web_api_port)
                self.logger.info(f"✅ Web API started on port {self.config.web_api_port}")
            elif self.config.enable_web_api:
                self.logger.warning("⚠️ Web API 配置启用但不可用")
            else:
                self.logger.info("💡 Web API 已关闭 - 优化性能模式")
                
            self.logger.info("✅ Python Supervisor initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize supervisor: {e}")
            return False
            
    def _convert_config_to_cpp(self) -> 'arp_core_cpp.Config':
        """将Python配置转换为C++配置"""
        config_dict = {
            'max_worker_threads': self.config.performance.max_worker_threads,
            'packet_batch_size': self.config.performance.packet_batch_size,
            'packet_batch_timeout': self.config.performance.packet_batch_timeout,
            'interface': self.config.network.interface,
            'gateway_ip': self.config.network.gateway_ip,
            'attack_timeout': self.config.attack.attack_timeout,
            'max_concurrent_attacks': self.config.attack.max_concurrent_attacks,
            'cooldown_time': self.config.attack.cooldown_time,
            'arp_cache_ttl': self.config.cache.arp_cache_ttl,
            'attack_cache_ttl': self.config.cache.attack_cache_ttl,
            'target_info_ttl': self.config.cache.target_info_ttl,
        }
        
        return arp_core_cpp.config_from_dict(config_dict)
        

    def run(self):
        """运行主循环 - 启动C++核心并监控"""
        self.running = True
        self.logger.info("🚀 Starting C++ ARP Processor...")
        
        try:
            # 🔧 启动C++核心处理器
            self.cpp_processor.start()
            self.logger.info("✅ C++ ARP Processor started successfully")
            
            # 🔧 启动监控线程
            self._start_monitoring()
            
            # 🔧 主线程等待C++处理器运行
            self.logger.info("📊 Monitoring C++ processor performance...")
            
            while self.running and self.cpp_processor.is_running():
                try:
                    # 每5秒检查一次状态
                    time.sleep(5)
                    
                    # 获取C++统计信息
                    cpp_stats = self.cpp_processor.get_statistics()
                    self.stats['last_cpp_stats'] = cpp_stats
                    
                    # 输出关键指标
                    self.logger.info(
                        f"📈 C++ Stats: "
                        f"Processed={cpp_stats.packets_processed}, "
                        f"Attacks={cpp_stats.attacks_launched}, "
                        f"Rate={cpp_stats.processing_rate:.1f}pps, "
                        f"Hit Rate={cpp_stats.hit_rate:.1f}%"
                    )
                    
                except KeyboardInterrupt:
                    self.logger.info("🛑 Received interrupt signal")
                    break
                except Exception as e:
                    self.logger.error(f"❌ Error in monitoring loop: {e}")
                    time.sleep(1)
                    
        except Exception as e:
            self.logger.error(f"❌ Error running supervisor: {e}")
        finally:
            self._shutdown()
            
    def _start_monitoring(self):
        """启动监控线程"""
        def monitor():
            self.logger.info("📊 Performance monitoring thread started")
            
            while self.running:
                try:
                    if self.cpp_processor and self.cpp_processor.is_running():
                        # 更新Python运行时间
                        self.stats['python_uptime'] = time.time() - self.stats['start_time']
                        
                        # 检查C++处理器健康状态
                        cpp_stats = self.cpp_processor.get_statistics()
                        
                        # 检测异常情况
                        if cpp_stats.processing_rate < 1.0:
                            self.logger.warning("⚠️ Low processing rate detected")
                        
                        if cpp_stats.hit_rate < 10.0:
                            self.logger.warning("⚠️ Low cache hit rate detected")
                            
                    time.sleep(10)  # 每10秒监控一次
                    
                except Exception as e:
                    self.logger.error(f"❌ Error in monitoring thread: {e}")
                    time.sleep(5)
                    
            self.logger.info("📊 Performance monitoring thread stopped")
            
        self.monitor_thread = threading.Thread(target=monitor, daemon=True)
        self.monitor_thread.start()
        
    def get_statistics(self) -> Dict:
        """获取综合统计信息"""
        stats = {
            'python_supervisor': {
                'uptime': time.time() - self.stats['start_time'],
                'status': 'running' if self.running else 'stopped'
            }
        }
        
        if self.cpp_processor:
            try:
                cpp_stats = self.cpp_processor.get_statistics()
                stats['cpp_processor'] = {
                    'packets_captured': cpp_stats.packets_captured,
                    'packets_processed': cpp_stats.packets_processed,
                    'attacks_launched': cpp_stats.attacks_launched,
                    'attacks_successful': cpp_stats.attacks_successful,
                    'processing_rate': cpp_stats.processing_rate,
                    'cache_hit_rate': cpp_stats.hit_rate,
                    'uptime_seconds': cpp_stats.uptime.total_seconds(),
                    'status': 'running' if self.cpp_processor.is_running() else 'stopped'
                }
            except Exception as e:
                stats['cpp_processor'] = {'error': str(e)}
                
        return stats
    def _shutdown(self):
        """清理资源"""
        self.logger.info("🛑 Shutting down Python Supervisor...")
        self.running = False
        
        # 停止C++处理器
        if self.cpp_processor:
            self.logger.info("🛑 Stopping C++ processor...")
            self.cpp_processor.stop()
            
        # 停止Web API
        if self.web_api:
            self.logger.info("🛑 Stopping Web API...")
            self.web_api.stop()
            
        # 等待监控线程结束
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
            
        # 打印最终统计信息
        self._print_final_stats()
        
    def _print_final_stats(self):
        """打印最终统计信息"""
        runtime = time.time() - self.stats['start_time']
        
        self.logger.info("=" * 80)
        self.logger.info("🎯 Python Supervisor Final Report")
        self.logger.info("=" * 80)
        self.logger.info(f"⏱️ Runtime: {runtime:.2f} seconds")
        
        if self.stats['last_cpp_stats']:
            cpp_stats = self.stats['last_cpp_stats']
            self.logger.info(f"📦 Packets processed: {cpp_stats.packets_processed}")
            self.logger.info(f"🎯 Attacks launched: {cpp_stats.attacks_launched}")
            self.logger.info(f"✅ Attacks successful: {cpp_stats.attacks_successful}")
            self.logger.info(f"⚡ Processing rate: {cpp_stats.processing_rate:.2f} pps")
            self.logger.info(f"💾 Cache hit rate: {cpp_stats.hit_rate:.2f}%")
        
        self.logger.info("=" * 80)

def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="ARP Spoofer Python Supervisor")
    parser.add_argument('-c', '--config', default='config.yaml',
                       help='Configuration file path')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='INFO', help='Log level')
    parser.add_argument('--web-api', action='store_true',
                       help='Enable web API interface')
    parser.add_argument('--web-port', type=int, default=8080,
                       help='Web API port')
    
    return parser.parse_args()

def signal_handler(signum, frame):
    """信号处理器"""
    print(f"\nReceived signal {signum}, shutting down...")
    sys.exit(0)

def main():
    """主函数"""
    try:
        # 解析命令行参数
        args = parse_arguments()
        
        # 设置信号处理
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
        # 加载配置
        config = Config.load_from_file(args.config)
        
        # 命令行参数覆盖配置文件
        if args.log_level:
            config.log_level = args.log_level
        if args.web_api:
            config.enable_web_api = True
        if args.web_port:
            config.web_api_port = args.web_port
            
        # 创建并运行监督者
        print("🔧 Creating PythonSupervisor...")
        supervisor = PythonSupervisor(config)
        
        print("🔧 Initializing supervisor...")
        if supervisor.initialize():
            print("🚀 Running supervisor...")
            supervisor.run()
        else:
            print("❌ Failed to initialize supervisor")
            sys.exit(1)
            
    except Exception as e:
        print(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
