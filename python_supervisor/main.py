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
    print(f"📦 Module version: {arp_core_cpp.__version__}")
    print(f"📋 Description: {arp_core_cpp.__description__}")
except ImportError as e:
    print(f"❌ Failed to import C++ core module: {e}")
    print("Please build the C++ module first:")
    print("  cd cpp_core && mkdir build && cd build")
    print("  cmake .. && make -j$(nproc)")
    print("  The module should be available as arp_core_cpp.so")
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
        if config.web_api.enabled and WEB_API_AVAILABLE:
            self.web_api = WebAPI(self, config)
        else:
            self.web_api = None
            if config.web_api.enabled and not WEB_API_AVAILABLE:
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
            
            # 🔧 创建ARP欺骗器（使用网络接口）
            interface = self.config.network.interface or "wlan0"  # 修正：使用network.interface
            self.arp_spoofer = arp_core_cpp.ARPSpoofer(interface)
            
            # 🔧 初始化ARP欺骗器
            if not self.arp_spoofer.initialize():
                self.logger.error("❌ Failed to initialize C++ ARP Spoofer")
                return False
            
            # 🔧 创建数据包嗅探器
            self.packet_sniffer = arp_core_cpp.PacketSniffer(interface)
            if not self.packet_sniffer.initialize():
                self.logger.error("❌ Failed to initialize packet sniffer")
                return False
            
            self.logger.info("✅ C++ Core initialized successfully")
            self.logger.info(f"📡 Using network interface: {interface}")
            
            # 启动Web API（如果启用且可用）
            if self.config.web_api.enabled and WEB_API_AVAILABLE:
                self.web_api = WebAPI(self)
                self.web_api.start(self.config.web_api.port)
                self.logger.info(f"✅ Web API started on port {self.config.web_api.port}")
            elif self.config.web_api.enabled:
                self.logger.warning("⚠️ Web API 配置启用但不可用")
            else:
                self.logger.info("💡 Web API 已关闭 - 优化性能模式")
            
            self.logger.info("✅ Python Supervisor initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize supervisor: {e}")
            return False
            
    def run(self):
        """运行主循环 - 启动C++核心并监控"""
        self.running = True
        self.logger.info("🚀 Starting C++ Core Components...")
        
        try:
            # 🔧 启动数据包捕获
            self.packet_sniffer.start_capture()
            self.logger.info("✅ Packet capture started")
            
            # 🔧 启动监控线程
            self._start_monitoring()
            
            # 🔧 保持主线程运行
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.logger.info("� Received interrupt signal...")
            self.shutdown()
        except Exception as e:
            self.logger.error(f"❌ Error in main loop: {e}")
            self.shutdown()
            
            # 🔧 主线程等待C++处理器运行
            self.logger.info("📊 Monitoring C++ processor performance...")
            
            while self.running and self.cpp_processor.is_running():
                try:
                    # 每5秒检查一次状态
                    time.sleep(5)
                    
                    # 获取C++统计信息
                    cpp_stats = self.cpp_processor.get_statistics()
                    self.stats['last_cpp_stats'] = cpp_stats
                    
                    # 🔧 输出更详细的关键指标，类似旧版本
                    self.logger.info(
                        f"� [MainThread] C++ Core Stats: "
                        f"📡 Captured={cpp_stats.packets_captured}, "
                        f"⚙️ Processed={cpp_stats.packets_processed}, "
                        f"🎯 Attacks={cpp_stats.attacks_launched}, "
                        f"✅ Success={cpp_stats.attacks_successful}, "
                        f"📈 Rate={cpp_stats.processing_rate:.1f}pps, "
                        f"💯 Hit Rate={cpp_stats.hit_rate:.1f}%"
                    )
                    
                    # 🔧 添加状态检查和警告
                    if cpp_stats.packets_captured == 0:
                        self.logger.warning("⚠️ No packets being captured - using simulation mode")
                    
                    if cpp_stats.processing_rate < 10.0:
                        self.logger.warning(f"⚠️ Low processing rate: {cpp_stats.processing_rate:.1f}pps")
                    
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
                    # 更新Python运行时间
                    self.stats['python_uptime'] = time.time() - self.stats['start_time']
                    
                    # 获取ARP欺骗器统计信息
                    if hasattr(self, 'arp_spoofer'):
                        packets_sent = self.arp_spoofer.get_total_packets_sent()
                        sessions = self.arp_spoofer.get_total_sessions()
                        active_sessions = self.arp_spoofer.get_active_sessions_count()
                        active_targets = self.arp_spoofer.get_active_targets()
                        
                        # 获取线程池统计
                        queue_sizes = self.arp_spoofer.get_thread_pool_queue_sizes()
                        completion_rate = self.arp_spoofer.get_thread_pool_completion_rate()
                        
                        # 检测异常情况
                        if completion_rate < 90.0:
                            self.logger.warning(f"⚠️ 线程池完成率较低: {completion_rate:.1f}%")
                        
                        # 检查线程池负载均衡
                        if queue_sizes and max(queue_sizes) > min(queue_sizes) * 3:
                            self.logger.warning("⚠️ 线程池负载不均衡")
                        
                        # 定期输出统计信息
                        self.logger.info(
                            f"📈 Stats: 📤 Sent={packets_sent}, 🎯 Active={active_sessions}, "
                            f"📊 Rate={completion_rate:.1f}%, 🧵 Queues={len(queue_sizes)}"
                        )
                    
                    # 获取数据包嗅探器统计
                    if hasattr(self, 'packet_sniffer'):
                        packet_count = self.packet_sniffer.get_packet_count()
                        if packet_count == 0:
                            self.logger.warning("⚠️ 没有捕获到数据包 - 检查网络接口和权限")
                    
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
        
        # 停止ARP欺骗器
        if hasattr(self, 'arp_spoofer'):
            self.logger.info("🛑 Stopping ARP Spoofer...")
            self.arp_spoofer.shutdown()
            
        # 停止数据包嗅探器
        if hasattr(self, 'packet_sniffer'):
            self.logger.info("🛑 Stopping Packet Sniffer...")
            self.packet_sniffer.stop_capture()
        
        # 停止Web API
        if hasattr(self, 'web_api') and self.web_api:
            self.logger.info("🛑 Stopping Web API...")
            try:
                self.web_api.stop()
            except:
                pass
            
        # 等待监控线程结束
        if hasattr(self, 'monitor_thread') and self.monitor_thread.is_alive():
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

    def start_attack(self, target_ip: str, target_mac: str = "", gateway_ip: str = "", gateway_mac: str = ""):
        """手动启动对指定目标的攻击"""
        try:
            if not hasattr(self, 'arp_spoofer'):
                self.logger.error("❌ ARP Spoofer not initialized")
                return False
            
            # 如果未提供网关信息，使用默认值
            if not gateway_ip:
                gateway_ip = self.config.network.gateway_ip or "10.17.0.1"  # 使用实际网关
            if not gateway_mac:
                gateway_mac = "00:11:22:33:44:55"  # 简化：使用默认MAC
            if not target_mac:
                target_mac = "aa:bb:cc:dd:ee:ff"   # 简化：使用默认MAC
                
            self.logger.info(f"🎯 Starting attack on {target_ip} via gateway {gateway_ip}")
            
            success = self.arp_spoofer.start_spoofing(target_ip, gateway_ip, target_mac, gateway_mac)
            if success:
                self.logger.info(f"✅ Attack on {target_ip} started successfully")
            else:
                self.logger.error(f"❌ Failed to start attack on {target_ip}")
                
            return success
            
        except Exception as e:
            self.logger.error(f"❌ Error starting attack on {target_ip}: {e}")
            return False
    
    def stop_attack(self, target_ip: str):
        """停止对指定目标的攻击"""
        try:
            if not hasattr(self, 'arp_spoofer'):
                self.logger.error("❌ ARP Spoofer not initialized")
                return False
                
            self.logger.info(f"🛑 Stopping attack on {target_ip}")
            success = self.arp_spoofer.stop_spoofing(target_ip)
            
            if success:
                self.logger.info(f"✅ Attack on {target_ip} stopped successfully")
            else:
                self.logger.warning(f"⚠️ Target {target_ip} was not being attacked")
                
            return success
            
        except Exception as e:
            self.logger.error(f"❌ Error stopping attack on {target_ip}: {e}")
            return False

def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="ARP Spoofer Python Supervisor")
    parser.add_argument('-c', '--config', default='config.yaml',
                       help='Configuration file path')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       help='Log level (overrides config file)')
    parser.add_argument('--web-api', action='store_true',
                       help='Enable web API interface')
    parser.add_argument('--web-port', type=int,
                       help='Web API port (overrides config file)')
    # 新增网络配置参数
    parser.add_argument('--interface', 
                       help='Network interface (overrides config file)')
    parser.add_argument('--gateway-ip',
                       help='Gateway IP address (overrides config file)')
    
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
    
        # 🔧 优先级：默认值 < YAML配置文件 < 命令行参数
        # 加载配置（第一步：YAML文件 - 主要配置来源）
        config = Config.load_from_file(args.config)
        print(f"📋 Loaded config from: {args.config}")
        
        # 命令行参数覆盖（第二步：仅在明确指定时覆盖YAML）
        overrides = []
        if args.log_level:
            config.logging.level = args.log_level
            overrides.append(f"log_level={args.log_level}")
        if args.web_api:
            config.web_api.enabled = True
            overrides.append("web_api=enabled")
        if args.web_port:
            config.web_api.port = args.web_port
            overrides.append(f"web_port={args.web_port}")
        if args.interface:
            config.network.interface = args.interface
            overrides.append(f"interface={args.interface}")
        if args.gateway_ip:
            config.network.gateway_ip = args.gateway_ip
            overrides.append(f"gateway_ip={args.gateway_ip}")
            
        # 显示配置优先级信息
        if overrides:
            print(f"🔧 Command line overrides: {', '.join(overrides)}")
        else:
            print("✅ Using pure YAML configuration (no command line overrides)")
            
        # 打印最终使用的关键配置
        print(f"📋 Final config - Interface: {config.network.interface}, Gateway: {config.network.gateway_ip}")
        print(f"📋 Performance - Threads: {config.performance.max_worker_threads}, Attack freq: {getattr(config.attack, 'attack_frequency', 'default')}")
        
        # 创建并运行监督者
        print("🔧 Creating PythonSupervisor...")
        supervisor = PythonSupervisor(config)
        
        print("🔧 Initializing supervisor...")
        if supervisor.initialize():
            print("🚀 Running supervisor...")
            
            # 🔧 添加测试攻击（可选）
            # 在生产环境中，攻击目标应该通过API或配置文件指定
            # supervisor.start_attack("192.168.1.100")  # 示例攻击目标
            
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
